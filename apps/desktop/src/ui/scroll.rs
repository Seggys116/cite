use std::cell::RefCell;
use std::collections::HashMap;

use gpui::{
    App, Div, ElementId, ScrollHandle, ScrollWheelEvent, SharedString, Stateful, Window, div,
    point, prelude::*, px,
};

thread_local! {
    static HANDLES: RefCell<HashMap<SharedString, ScrollHandle>> = RefCell::new(HashMap::new());
}

// Slack for float rounding when deciding whether an offset still lies inside its range.
const EDGE_SLACK: f32 = 0.5;

// One handle per key for the life of the app, so an area keeps its position across frames.
pub fn scroll_handle(key: &SharedString) -> ScrollHandle {
    HANDLES.with(|map| map.borrow_mut().entry(key.clone()).or_default().clone())
}

// A vertically scrolling area that keeps the wheel to itself until it reaches an end.
pub fn scroll_area(key: impl Into<SharedString>) -> Stateful<Div> {
    let key = key.into();
    let handle = scroll_handle(&key);
    scroll_area_with(key, &handle)
}

pub fn scroll_area_with(key: impl Into<SharedString>, handle: &ScrollHandle) -> Stateful<Div> {
    div()
        .id(ElementId::Name(key.into()))
        .min_h_0()
        .overflow_y_scroll()
        .track_scroll(handle)
        .on_scroll_wheel(isolate(handle.clone()))
}

// GPUI applies the wheel to every scroller under the pointer, so this runs after the inner one moved and stops the event there unless it hit an end.
fn isolate(handle: ScrollHandle) -> impl Fn(&ScrollWheelEvent, &mut Window, &mut App) + 'static {
    move |event, window, cx| {
        let delta = event.delta.pixel_delta(window.line_height());
        // A vertical scroller also takes a sideways swipe when there is no vertical motion.
        if delta.y == px(0.) && delta.x == px(0.) {
            return;
        }
        let offset = handle.offset();
        let limit = f32::from(handle.max_offset().height);
        let value = f32::from(offset.y);
        if within(value, limit) {
            cx.stop_propagation();
            return;
        }
        handle.set_offset(point(offset.x, px(clamp_offset(value, limit))));
    }
}

// Offsets run from 0 at the start to -limit at the end.
fn within(value: f32, limit: f32) -> bool {
    value <= EDGE_SLACK && value >= -limit.max(0.0) - EDGE_SLACK
}

fn clamp_offset(value: f32, limit: f32) -> f32 {
    value.min(0.0).max(-limit.max(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_offset_inside_the_range_is_kept_by_the_inner_area() {
        assert!(within(0.0, 200.0));
        assert!(within(-120.0, 200.0));
        assert!(within(-200.0, 200.0));
    }

    #[test]
    fn an_offset_past_either_end_is_handed_to_the_page() {
        assert!(!within(12.0, 200.0));
        assert!(!within(-230.0, 200.0));
        assert!(!within(-4.0, 0.0));
        assert!(!within(4.0, 0.0));
    }

    #[test]
    fn clamping_returns_to_the_nearest_end() {
        assert_eq!(clamp_offset(30.0, 200.0), 0.0);
        assert_eq!(clamp_offset(-260.0, 200.0), -200.0);
        assert_eq!(clamp_offset(-50.0, 200.0), -50.0);
        assert_eq!(clamp_offset(-50.0, 0.0), 0.0);
    }

    #[test]
    fn the_same_key_returns_the_same_handle() {
        let key = SharedString::from("scroll-test");
        let a = scroll_handle(&key);
        a.set_offset(point(px(0.), px(-40.)));
        assert_eq!(scroll_handle(&key).offset().y, px(-40.));
    }
}
