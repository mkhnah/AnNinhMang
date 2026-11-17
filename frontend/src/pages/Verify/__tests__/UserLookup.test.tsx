import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, expect, it, vi } from 'vitest';
import { UserLookup } from '../UserLookup';

const mocks = vi.hoisted(() => ({search: vi.fn()}));
vi.mock('../../../api/users', () => ({usersApi: {search: mocks.search}}));
const person = {id:'12345678-1111-4444-aaaa-123456789012', full_name:'Nguyễn Minh An', email:'an@cyber.edu', status:'ACTIVE'};
const page = {items:[person], total:1, limit:20, offset:0};
const show = (route = '/verify/users') => render(<MemoryRouter initialEntries={[route]}><UserLookup /></MemoryRouter>);
const type = (text: string) => fireEvent.change(screen.getByRole('searchbox', {name:'Tìm kiếm người dùng'}), {target:{value:text}});
const submit = () => fireEvent.click(screen.getByRole('button', {name:'Tìm kiếm'}));
beforeEach(() => vi.clearAllMocks());

it('waits for a search, then shows name, email, full UUID and account status', async () => {
    mocks.search.mockResolvedValue(page);
    show();
    expect(mocks.search).not.toHaveBeenCalled();
    expect(screen.getByRole('button', {name:'Tìm kiếm'})).toBeDisabled();
    type('Nguyễn Minh'); submit();
    expect(await screen.findByText(person.full_name)).toBeInTheDocument();
    expect(screen.getByText(person.email)).toBeInTheDocument();
    expect(screen.getByText(person.id)).toBeInTheDocument();
    expect(screen.getByText('Đang hoạt động')).toBeInTheDocument();
    expect(mocks.search).toHaveBeenCalledWith('Nguyễn Minh', 0, expect.any(AbortSignal));
});

it('looks up the UUID from the certificate link and compares it with a name search', async () => {
    mocks.search.mockResolvedValue(page);
    show('/verify/users?uuid='+person.id);
    expect(await screen.findByText('Khớp UUID cần đối chiếu')).toBeInTheDocument();
    expect(mocks.search).toHaveBeenCalledWith(person.id, 0, expect.any(AbortSignal));
    mocks.search.mockResolvedValue({...page, items:[{...person, id:'different-uuid', status:'DISABLED'}]});
    type('another person'); submit();
    expect(await screen.findByText('Không khớp UUID cần đối chiếu')).toBeInTheDocument();
    expect(screen.getByText('Đã vô hiệu hóa')).toBeInTheDocument();
});

it('copies the full UUID', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {configurable:true, value:{writeText}});
    mocks.search.mockResolvedValue(page);
    show(); type('an@cyber.edu'); submit();
    fireEvent.click(await screen.findByRole('button', {name:'Sao chép UUID của '+person.full_name}));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(person.id));
    expect(await screen.findByText('Đã sao chép UUID: '+person.id)).toBeInTheDocument();
});

it('discards a late response after the search query changes', async () => {
    let resolve!: (value:unknown) => void;
    mocks.search.mockImplementation(() => new Promise(r => {resolve=r;}));
    show(); type('old-query'); submit();
    const signal = mocks.search.mock.calls[0][2] as AbortSignal;
    type('new-query');
    expect(signal.aborted).toBe(true);
    await act(async () => resolve(page));
    expect(screen.queryByText(person.full_name)).not.toBeInTheDocument();
});

it('shows no results and allows retrying a failed request', async () => {
    mocks.search.mockRejectedValueOnce(new Error('network')).mockResolvedValueOnce({...page, items:[], total:0});
    show(); type('missing'); submit();
    expect(await screen.findByRole('alert')).toHaveTextContent('Không thể tìm kiếm');
    submit();
    expect(await screen.findByText('Không tìm thấy người dùng phù hợp.')).toBeInTheDocument();
});

it('requests the next page without reusing the previous results', async () => {
    mocks.search.mockResolvedValueOnce({...page,total:21}).mockResolvedValueOnce({...page,offset:20,total:21});
    show(); type('cyber.edu'); submit();
    fireEvent.click(await screen.findByRole('button', {name:'Trang sau'}));
    await waitFor(() => expect(mocks.search).toHaveBeenLastCalledWith('cyber.edu',20,expect.any(AbortSignal)));
    expect(await screen.findByText('Trang 2 / 2')).toBeInTheDocument();
    expect(screen.getByRole('button', {name:'Trang sau'})).toBeDisabled();
});

it('aborts lookup when unmounted', () => {
    mocks.search.mockImplementation(() => new Promise(() => undefined));
    const view = show(); type('pending'); submit();
    const signal = mocks.search.mock.calls[0][2] as AbortSignal;
    view.unmount(); expect(signal.aborted).toBe(true);
});
