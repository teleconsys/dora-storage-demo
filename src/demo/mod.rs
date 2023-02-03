use colored::Colorize;

pub mod node;
pub mod run;
pub mod run_iota;

pub fn generic_log_target(session_id: &str) -> String {
    session_id.chars().take(10).collect::<String>().yellow().to_string()
}