export const MAX_PDF_BYTES = 20 * 1024 * 1024;
export const MAX_CANVAS_PIXELS = 4_000_000;
export function boundedScale(width: number, height: number, scale: number): number {
    if (!Number.isFinite(width * height) || width <= 0 || height <= 0) throw new Error('Kích thước trang không hợp lệ');
    return scale * Math.min(1, Math.sqrt(MAX_CANVAS_PIXELS / (width * height)), 4096 / Math.max(width, height));
}
