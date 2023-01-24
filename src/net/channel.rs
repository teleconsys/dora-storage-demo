use std::fmt::Display;

pub trait Sender<T>: Clone + Send {
    fn send(&self, t: T) -> Result<(), SendError<T>>;
}
impl<T: Send> Sender<T> for std::sync::mpsc::Sender<T> {
    fn send(&self, t: T) -> Result<(), SendError<T>> {
        self.send(t).map_err(|e| e.into())
    }
}
impl<T: Send> Sender<T> for tokio::sync::broadcast::Sender<T> {
    fn send(&self, t: T) -> Result<(), SendError<T>> {
        self.send(t).map_err(|e| e.into()).map(|_| ())
    }
}

pub struct SendError<T>(pub T);
impl<T> From<std::sync::mpsc::SendError<T>> for SendError<T> {
    fn from(value: std::sync::mpsc::SendError<T>) -> Self {
        SendError(value.0)
    }
}
impl<T> From<tokio::sync::broadcast::error::SendError<T>> for SendError<T> {
    fn from(value: tokio::sync::broadcast::error::SendError<T>) -> Self {
        SendError(value.0)
    }
}

impl<T: Display> Display for SendError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub trait Receiver<T> {
    fn recv(&mut self) -> Result<T, RecvError>;
}
impl<T> Receiver<T> for std::sync::mpsc::Receiver<T> {
    fn recv(&mut self) -> Result<T, RecvError> {
        let rec: &std::sync::mpsc::Receiver<T> = self;
        rec.recv().map_err(|e| e.into())
    }
}
impl<T: Clone> Receiver<T> for tokio::sync::broadcast::Receiver<T> {
    fn recv(&mut self) -> Result<T, RecvError> {
        futures::executor::block_on(self.recv()).map_err(|e| e.into())
    }
}

#[derive(Debug)]
pub struct RecvError;

impl From<std::sync::mpsc::RecvError> for RecvError {
    fn from(_value: std::sync::mpsc::RecvError) -> Self {
        Self
    }
}

impl From<tokio::sync::broadcast::error::RecvError> for RecvError {
    fn from(_value: tokio::sync::broadcast::error::RecvError) -> Self {
        Self
    }
}
