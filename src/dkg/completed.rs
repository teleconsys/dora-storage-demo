use crate::fsm::State;

struct CompletedDkg {}
impl State for CompletedDkg {
    fn initialize(&self) -> Vec<M> {
        todo!()
    }

    fn deliver(&mut self, message: M) -> crate::fsm::DeliveryStatus<M> {
        todo!()
    }

    fn advance(&self) -> Result<crate::fsm::Transition<M>, anyhow::Error> {
        todo!()
    }
}
