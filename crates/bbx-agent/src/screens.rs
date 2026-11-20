//! Optional screenshot ring: low-resolution grayscale PNGs of the whole
//! virtual screen, kept in memory and written out only for incidents.

use bbx_core::time::now_ft;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN};

pub struct Ring {
    frames: VecDeque<(i64, Vec<u8>)>,
    last: Option<Instant>,
}

impl Ring {
    pub fn new() -> Self {
        Self { frames: VecDeque::new(), last: None }
    }

    pub fn due(&self, interval_s: u64) -> bool {
        self.last.is_none_or(|t| t.elapsed() >= Duration::from_secs(interval_s))
    }

    pub fn clear(&mut self) {
        self.frames.clear();
    }

    pub fn frames(&self) -> impl Iterator<Item = &(i64, Vec<u8>)> {
        self.frames.iter()
    }

    pub fn capture(&mut self, width: u32, keep: usize) {
        self.last = Some(Instant::now());
        if let Some(png) = grab(width) {
            self.frames.push_back((now_ft(), png));
            while self.frames.len() > keep.max(1) {
                self.frames.pop_front();
            }
        }
    }
}

/// Capture the virtual screen scaled to `width`, as 8-bit grayscale PNG.
/// Returns None on the secure desktop / lock screen (BitBlt fails there).
fn grab(width: u32) -> Option<Vec<u8>> {
    unsafe {
        let (x, y) = (GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN));
        let (w, h) = (GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN));
        if w <= 0 || h <= 0 {
            return None;
        }
        let tw = (width as i32).min(w).max(16);
        let th = ((h as i64 * tw as i64) / w as i64).max(16) as i32;
        let screen = GetDC(std::ptr::null_mut());
        if screen.is_null() {
            return None;
        }
        let mem = CreateCompatibleDC(screen);
        let bmp = CreateCompatibleBitmap(screen, tw, th);
        let old = SelectObject(mem, bmp);
        SetStretchBltMode(mem, HALFTONE);
        SetBrushOrgEx(mem, 0, 0, std::ptr::null_mut());
        let ok = StretchBlt(mem, 0, 0, tw, th, screen, x, y, w, h, SRCCOPY) != 0;
        let mut bi: BITMAPINFO = std::mem::zeroed();
        bi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bi.bmiHeader.biWidth = tw;
        bi.bmiHeader.biHeight = -th; // top-down
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        let mut bgra = vec![0u8; (tw * th * 4) as usize];
        let lines = if ok { GetDIBits(mem, bmp, 0, th as u32, bgra.as_mut_ptr().cast(), &mut bi, DIB_RGB_COLORS) } else { 0 };
        SelectObject(mem, old);
        DeleteObject(bmp);
        DeleteDC(mem);
        ReleaseDC(std::ptr::null_mut(), screen);
        if lines == 0 {
            return None;
        }
        let gray: Vec<u8> = bgra.chunks_exact(4).map(|p| ((p[2] as u32 * 77 + p[1] as u32 * 150 + p[0] as u32 * 29) >> 8) as u8).collect();
        encode_png(&gray, tw as u32, th as u32)
    }
}

pub fn encode_png(gray: &[u8], w: u32, h: u32) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, w, h);
        enc.set_color(png::ColorType::Grayscale);
        enc.set_depth(png::BitDepth::Eight);
        enc.set_compression(png::Compression::Best);
        let mut wr = enc.write_header().ok()?;
        wr.write_image_data(gray).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn png_encodes() {
        let img = vec![128u8; 64 * 32];
        let p = super::encode_png(&img, 64, 32).unwrap();
        assert_eq!(&p[1..4], b"PNG");
    }

    #[test]
    fn live_capture() {
        // On a headless/locked session this returns None, which is fine.
        if let Some(p) = super::grab(320) {
            assert_eq!(&p[1..4], b"PNG");
            eprintln!("captured {} bytes", p.len());
        }
    }
}
