//! The guest's Linux side: the init, the agent, exec, builds, the NIC,
//! and the idle memory trim.

pub mod agent;
pub mod build;
pub mod exec;
pub mod init;
pub mod net;
pub mod sys;
pub mod trim;
