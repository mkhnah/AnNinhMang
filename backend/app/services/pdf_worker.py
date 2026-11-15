"""Untrusted parser process: stdin binary, stdout bounded status, never rewrite PDF."""
import sys
import resource
import signal
import json
import os
import time


_STAGE = "bootstrap"
_STARTED = time.monotonic()

def status(ok, reason="complete", signum=None):
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {"ok": ok, "diagnostics": {
        "stage": _STAGE, "reason": reason, "signal": signum,
        "cpu_seconds": round(usage.ru_utime + usage.ru_stime, 6),
        "wall_seconds": round(time.monotonic() - _STARTED, 6),
        "cpu_limit": list(resource.getrlimit(resource.RLIMIT_CPU)),
    }}

def terminate(signum, frame):
    # No exception text, PDF bytes, paths or secrets leave the parser.
    print(json.dumps(status(False, "signal", signum)), flush=True)
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)

signal.signal(signal.SIGXCPU, terminate)
signal.signal(signal.SIGALRM, terminate)

def main():
    global _STAGE
    _STAGE = "limits"
    timeout, memory, max_objects, max_depth = map(int, sys.argv[1:])
    resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024 * 1024, 128 * 1024 * 1024))
    # RLIMIT_AS is not a reliable RSS limit on macOS. Parent monitors actual RSS.
    if sys.platform != 'darwin':
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    signal.alarm(timeout + 1)
    _STAGE = "import"
    from pypdf import PdfReader
    from pypdf.generic import DictionaryObject, ArrayObject, IndirectObject, NameObject
    import tempfile
    blocked = {'/JavaScript', '/JS', '/Launch', '/OpenAction', '/AA', '/SubmitForm',
               '/EmbeddedFiles', '/EmbeddedFile', '/EF', '/RichMedia', '/XFA', '/GoToR', '/GoToE', '/ImportData'}
    # Worker temp lives in repo via TMPDIR from parent; rolls to disk after 1MB.
    _STAGE = "spool"
    with tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as source:
        while chunk := sys.stdin.buffer.read(65536):
            source.write(chunk)
        source.seek(0)
        _STAGE = "parse"
        reader = PdfReader(source, strict=True)
        if reader.is_encrypted:
            raise ValueError('Encrypted PDFs unsupported')
        if not reader.trailer.get('/Root') or not len(reader.pages):
            raise ValueError('Missing PDF root/pages')
        seen_refs, seen_containers = set(), set()
        count = 0

        def visit(obj, depth=0):
            nonlocal count
            count += 1
            if count > max_objects or depth > max_depth:
                raise ValueError('PDF object/depth budget exceeded')
            if isinstance(obj, IndirectObject):
                key = (obj.idnum, obj.generation)
                if key in seen_refs:
                    return
                seen_refs.add(key)
                visit(obj.get_object(), depth + 1)
            elif isinstance(obj, (DictionaryObject, ArrayObject)):
                if id(obj) in seen_containers:
                    return
                seen_containers.add(id(obj))
                if isinstance(obj, DictionaryObject):
                    for key, value in obj.items():
                        if str(key) in blocked:
                            raise ValueError('Active PDF content forbidden')
                        visit(value, depth + 1)
                else:
                    for item in obj:
                        visit(item, depth + 1)
            elif isinstance(obj, NameObject) and str(obj) in blocked:
                raise ValueError('Active PDF action forbidden')

        _STAGE = "traverse"
        visit(reader.trailer)
        # Include unreachable objects and compressed object streams, not just catalog.
        for generation, objects in reader.xref.items():
            for object_id in objects:
                if object_id:
                    visit(IndirectObject(object_id, generation, reader))
        for object_id in reader.xref_objStm:
            visit(IndirectObject(object_id, 0, reader))
    _STAGE = "complete"
    print(json.dumps(status(True)))


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        print(json.dumps(status(False, "parser_rejection")))
        sys.exit(1)
