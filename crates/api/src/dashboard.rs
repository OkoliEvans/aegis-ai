use std::convert::Infallible;

use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures_util::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::AppState;

pub async fn sse_feed(
    State(state): State<AppState>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let receiver = state.notifier.subscribe();
    let stream = BroadcastStream::new(receiver)
        .filter_map(|message| async move { message.ok() })
        .map(|data| Ok(Event::default().data(data)));

    Sse::new(stream).keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
}
