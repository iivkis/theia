//! Separate Initial, Handshake and Application packet-number spaces.
//! Deliberately no 0-RTT space. Discarding a space is irreversible.
use super::packet::{Error, ReplayWindow};
use super::wire::MAX_VARINT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Space { Initial, Handshake, Application }

#[derive(Default)]
struct State {
    next: u64,
    receive: ReplayWindow,
    discarded: bool,
}

#[derive(Default)]
pub struct Spaces([State; 3]);

impl Spaces {
    fn get(&mut self, space: Space) -> Result<&mut State, Error> {
        let state = &mut self.0[space as usize];
        if state.discarded { Err(Error::Limit) } else { Ok(state) }
    }

    pub fn allocate(&mut self, space: Space) -> Result<u64, Error> {
        let state = self.get(space)?;
        if state.next > MAX_VARINT { return Err(Error::Limit); }
        let n = state.next;
        state.next += 1;
        Ok(n)
    }

    /// Call only for a successfully opened packet. Do not use both this
    /// receive window and a packet Reader as independent authorities.
    pub fn received(&mut self, space: Space, number: u64) -> Result<(), Error> {
        self.get(space)?.receive.accept(number)
    }

    pub fn largest_received(&mut self, space: Space) -> Result<Option<u64>, Error> {
        Ok(self.get(space)?.receive.largest())
    }

    pub fn discard(&mut self, space: Space) {
        self.0[space as usize] = State { discarded: true, ..State::default() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spaces_are_isolated_and_discard_is_permanent() {
        let mut s = Spaces::default();
        for space in [Space::Initial, Space::Handshake, Space::Application] {
            assert_eq!(s.allocate(space), Ok(0));
            assert_eq!(s.received(space, 0), Ok(()));
            assert_eq!(s.received(space, 0), Err(Error::Duplicate));
            assert_eq!(s.largest_received(space), Ok(Some(0)));
        }
        s.discard(Space::Initial);
        assert_eq!(s.allocate(Space::Initial), Err(Error::Limit));
        assert_eq!(s.received(Space::Initial, 1), Err(Error::Limit));
        assert_eq!(s.allocate(Space::Handshake), Ok(1));
        assert_eq!(s.allocate(Space::Application), Ok(1));
        s.0[Space::Application as usize].next = MAX_VARINT;
        assert_eq!(s.allocate(Space::Application), Ok(MAX_VARINT));
        assert_eq!(s.allocate(Space::Application), Err(Error::Limit));
    }
}
