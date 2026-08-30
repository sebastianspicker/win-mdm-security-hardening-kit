//! Standard-control Win32 view for the native audit launcher.

#![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;

use windows::{
    Win32::{
        Foundation::{HINSTANCE, HWND, LPARAM, WPARAM},
        Graphics::Gdi::{DEFAULT_GUI_FONT, GetStockObject},
        System::LibraryLoader::GetModuleHandleW,
        UI::{
            HiDpi::GetDpiForWindow,
            Input::KeyboardAndMouse::EnableWindow,
            WindowsAndMessaging::{
                BS_DEFPUSHBUTTON, ES_AUTOVSCROLL, ES_MULTILINE, ES_READONLY, HMENU, LB_ADDSTRING,
                LB_GETCURSEL, LB_SETCURSEL, LBS_NOTIFY, SendMessageW, SetWindowTextW,
                WINDOW_EX_STYLE, WINDOW_STYLE, WM_SETFONT, WS_BORDER, WS_CHILD, WS_GROUP,
                WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
            },
        },
    },
    core::{PCWSTR, Result, w},
};

use crate::controller::{AuditReport, CatalogItem};

pub const CAPABILITY_LIST: i32 = 1001;
pub const AUDIT_BUTTON: i32 = 1002;
pub const CANCEL_BUTTON: i32 = 1003;
pub const SELECTION_TEXT: i32 = 1004;
pub const STATUS_TEXT: i32 = 1005;
pub const RESULT_TEXT: i32 = 1006;
pub const OPEN_ARTIFACT_BUTTON: i32 = 1007;

/// Handles for the standard controls that Windows exposes to UI Automation.
#[derive(Clone, Copy)]
pub struct Controls {
    pub list: HWND,
    pub audit: HWND,
    pub cancel: HWND,
    pub open_artifact: HWND,
    selection: HWND,
    status: HWND,
    result: HWND,
}

/// Creates all controls atomically from the parent-window perspective.
pub unsafe fn create(parent: HWND, items: &[CatalogItem]) -> Result<Controls> {
    let instance = HINSTANCE(GetModuleHandleW(None)?.0);
    let list = control(
        parent,
        instance,
        w!("LISTBOX"),
        w!("Native capability catalog. Use arrow keys to select an audit."),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | WS_GROUP | WINDOW_STYLE(LBS_NOTIFY as u32),
        CAPABILITY_LIST,
    )?;
    for item in items {
        let label = wide(&format!("{:02}  {}", item.number, item.name));
        SendMessageW(
            list,
            LB_ADDSTRING,
            Some(WPARAM(0)),
            Some(LPARAM(label.as_ptr() as isize)),
        );
    }
    SendMessageW(list, LB_SETCURSEL, Some(WPARAM(0)), Some(LPARAM(0)));
    let selection = control(
        parent,
        instance,
        w!("STATIC"),
        w!("Selected capability details."),
        WS_CHILD | WS_VISIBLE,
        SELECTION_TEXT,
    )?;
    let audit = control(
        parent,
        instance,
        w!("BUTTON"),
        w!("Audit selected capability"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_DEFPUSHBUTTON as u32),
        AUDIT_BUTTON,
    )?;
    let cancel = control(
        parent,
        instance,
        w!("BUTTON"),
        w!("Cancel audit"),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        CANCEL_BUTTON,
    )?;
    // Hidden until the controller confirms that a returned artifact is a regular file.
    let open_artifact = control(
        parent,
        instance,
        w!("BUTTON"),
        w!("Open retained artifact"),
        WS_CHILD | WS_TABSTOP,
        OPEN_ARTIFACT_BUTTON,
    )?;
    let status = control(
        parent,
        instance,
        w!("STATIC"),
        w!("Status: Ready."),
        WS_CHILD | WS_VISIBLE,
        STATUS_TEXT,
    )?;
    let result = control(
        parent,
        instance,
        w!("EDIT"),
        w!("Results and errors appear here. This field is read-only."),
        WS_CHILD
            | WS_VISIBLE
            | WS_TABSTOP
            | WS_BORDER
            | WS_VSCROLL
            | WINDOW_STYLE((ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY) as u32),
        RESULT_TEXT,
    )?;
    let font = GetStockObject(DEFAULT_GUI_FONT);
    for handle in [
        list,
        selection,
        audit,
        cancel,
        open_artifact,
        status,
        result,
    ] {
        SendMessageW(
            handle,
            WM_SETFONT,
            Some(WPARAM(font.0 as usize)),
            Some(LPARAM(1)),
        );
    }
    let _ = EnableWindow(cancel, false);
    Ok(Controls {
        list,
        audit,
        cancel,
        open_artifact,
        selection,
        status,
        result,
    })
}

/// Returns the selected catalog index, if the list box has a valid selection.
pub unsafe fn selected_index(controls: Controls) -> Option<usize> {
    let selected = SendMessageW(
        controls.list,
        LB_GETCURSEL,
        Some(WPARAM(0)),
        Some(LPARAM(0)),
    )
    .0;
    usize::try_from(selected).ok()
}

/// Displays selection text using a real STATIC control for accessibility clients.
pub unsafe fn set_selection(controls: Controls, text: &str) -> Result<()> {
    set_text(controls.selection, text)
}

/// Displays the current status plus structured result or diagnostic in separate text controls.
pub unsafe fn set_report(controls: Controls, report: &AuditReport) -> Result<()> {
    set_text(controls.status, &format!("Status: {}", report.status))?;
    let body = match (&report.result, &report.error) {
        (result, None) if !result.is_empty() => result.clone(),
        (_, Some(error)) => format!("Error: {error}"),
        _ => String::new(),
    };
    set_text(controls.result, &body)
}

/// Updates controls so an audit cannot overlap and cancellation remains visible.
pub unsafe fn set_running(controls: Controls, running: bool) {
    let _ = EnableWindow(controls.list, !running);
    let _ = EnableWindow(controls.audit, !running);
    let _ = EnableWindow(controls.cancel, running);
}

/// Shows an artifact-open affordance only for a verified existing artifact.
pub unsafe fn set_artifact_visible(controls: Controls, visible: bool) {
    use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOW, ShowWindow};

    let _ = ShowWindow(
        controls.open_artifact,
        if visible { SW_SHOW } else { SW_HIDE },
    );
}

/// Lays out controls using current DPI while relying entirely on system colors and standard controls.
pub unsafe fn layout(controls: Controls, width: i32, height: i32) -> Result<()> {
    use windows::Win32::UI::WindowsAndMessaging::MoveWindow;

    let scale = i32::try_from(GetDpiForWindow(controls.list)).unwrap_or(96);
    let unit = |value: i32| value.saturating_mul(scale) / 96;
    let margin = unit(18);
    let gap = unit(12);
    let button_width = unit(220);
    let button_height = unit(34);
    let list_width = ((width - margin * 2) * 38 / 100).max(unit(230));
    let right_x = margin + list_width + gap;
    let right_width = (width - right_x - margin).max(unit(250));
    let bottom = height - margin;
    let buttons_y = bottom - button_height;
    let status_y = buttons_y - gap - unit(42);
    let result_y = status_y - gap - unit(220);
    let selection_height = (result_y - gap - margin).max(unit(70));
    MoveWindow(
        controls.list,
        margin,
        margin,
        list_width,
        (buttons_y - gap - margin).max(unit(160)),
        true,
    )?;
    MoveWindow(
        controls.selection,
        right_x,
        margin,
        right_width,
        selection_height,
        true,
    )?;
    MoveWindow(
        controls.result,
        right_x,
        result_y,
        right_width,
        unit(220),
        true,
    )?;
    MoveWindow(
        controls.status,
        right_x,
        status_y,
        right_width,
        unit(42),
        true,
    )?;
    MoveWindow(
        controls.audit,
        margin,
        buttons_y,
        button_width,
        button_height,
        true,
    )?;
    MoveWindow(
        controls.cancel,
        margin + button_width + gap,
        buttons_y,
        button_width,
        button_height,
        true,
    )?;
    MoveWindow(
        controls.open_artifact,
        margin + (button_width + gap) * 2,
        buttons_y,
        button_width,
        button_height,
        true,
    )
}

unsafe fn control(
    parent: HWND,
    instance: HINSTANCE,
    class: PCWSTR,
    label: PCWSTR,
    style: WINDOW_STYLE,
    id: i32,
) -> Result<HWND> {
    windows::Win32::UI::WindowsAndMessaging::CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        class,
        label,
        style,
        0,
        0,
        0,
        0,
        Some(parent),
        Some(control_menu(id)),
        Some(instance),
        None,
    )
}

unsafe fn set_text(control: HWND, value: &str) -> Result<()> {
    let text = wide(value);
    SetWindowTextW(control, PCWSTR(text.as_ptr()))
}

fn control_menu(id: i32) -> HMENU {
    let value = usize::try_from(id).expect("control identifiers are positive constants");
    HMENU(value as *mut c_void)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
