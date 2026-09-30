use std::io::{self, Write};
use std::path::Path;

use cite_core::{PackLimits, pack_dir};

use crate::{ManagerError, Result};

pub use crate::build::run_build_helper;

/// Must run before the helper forks anything; a process that already leads a group cannot start a session.
#[cfg(unix)]
fn enter_new_session() -> std::result::Result<(), rustix::io::Errno> {
    rustix::process::setsid().map(|_| ())
}

pub fn apply_build_limits() {
    #[cfg(unix)]
    {
        if let Err(err) = enter_new_session() {
            eprintln!("cite helper: could not start a new session: {err}");
        }
        clamp_rlimit(rustix::process::Resource::Nproc, 512);
        clamp_rlimit(rustix::process::Resource::Nofile, 4096);
        clamp_rlimit(rustix::process::Resource::Core, 0);
        clamp_rlimit(rustix::process::Resource::Fsize, 2 * 1024 * 1024 * 1024);
    }
}

#[cfg(unix)]
fn clamp_rlimit(resource: rustix::process::Resource, want: u64) {
    let hard = rustix::process::getrlimit(resource).maximum;
    let value = hard.map_or(want, |max| want.min(max));
    let _ = rustix::process::setrlimit(
        resource,
        rustix::process::Rlimit {
            current: Some(value),
            maximum: Some(value),
        },
    );
}

pub fn run_pack_helper(dir: &Path) -> Result<()> {
    let limits = PackLimits::default();
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    pack_dir(dir, &mut lock, &limits)?;
    lock.flush()?;
    Ok(())
}

pub fn run_clean_helper(job_dir: &Path) -> Result<()> {
    // The build uid can daemonize out of the process group, so signal every process with that uid.
    #[cfg(unix)]
    {
        signal_same_uid(rustix::process::Signal::TERM);
        std::thread::sleep(std::time::Duration::from_millis(200));
        kill_all_same_uid()?;
    }
    remove_job_tree(job_dir);
    Ok(())
}

/// The job directory is root-owned, so the build uid can empty it but not always unlink it; the manager's own wipe removes the remainder.
fn remove_job_tree(job_dir: &Path) {
    if job_dir.exists()
        && let Err(err) = std::fs::remove_dir_all(job_dir)
    {
        eprintln!(
            "cite helper: could not fully remove {}: {err}",
            job_dir.display()
        );
    }
}

/// The build uid must not be able to ptrace (and so stop) pid 1; the attach is always detached.
pub fn probe_ptrace_pid1() {
    #[cfg(target_os = "linux")]
    {
        let pid = nix::unistd::Pid::from_raw(1);
        match nix::sys::ptrace::attach(pid) {
            Ok(()) => {
                let _ = nix::sys::ptrace::detach(pid, None);
                println!("ptrace ATTACHED");
            }
            Err(err) => println!("ptrace DENIED {err}"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!("ptrace DENIED unsupported");
    }
}

#[cfg(unix)]
fn same_uid_pids() -> Option<Vec<i32>> {
    let me = std::process::id();
    let uid = rustix::process::geteuid().as_raw().to_string();
    let dir = std::fs::read_dir("/proc").ok()?;
    let mut pids = Vec::new();
    for entry in dir.flatten() {
        let Ok(pid_num) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if pid_num <= 1 || pid_num as u32 == me {
            continue;
        }
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid_num}/status")) else {
            continue;
        };
        let zombie = status.lines().any(|line| {
            line.strip_prefix("State:")
                .is_some_and(|s| s.trim_start().starts_with('Z'))
        });
        let same = status.lines().any(|line| {
            line.strip_prefix("Uid:")
                .and_then(|rest| rest.split_whitespace().next())
                .is_some_and(|first| first == uid)
        });
        if same && !zombie {
            pids.push(pid_num);
        }
    }
    Some(pids)
}

#[cfg(unix)]
fn signal_same_uid(sig: rustix::process::Signal) {
    let Some(pids) = same_uid_pids() else {
        return;
    };
    for pid_num in pids {
        if let Some(pid) = rustix::process::Pid::from_raw(pid_num) {
            let _ = rustix::process::kill_process(pid, sig);
        }
    }
}

/// Stops every process first so none can fork, then kills them; fails unless a final scan finds none left.
#[cfg(unix)]
fn kill_all_same_uid() -> Result<()> {
    kill_until_none(
        same_uid_pids,
        |pids| {
            for sig in [rustix::process::Signal::STOP, rustix::process::Signal::KILL] {
                for pid_num in pids {
                    if let Some(pid) = rustix::process::Pid::from_raw(*pid_num) {
                        let _ = rustix::process::kill_process(pid, sig);
                    }
                }
            }
        },
        200,
        std::time::Duration::from_millis(20),
    )
}

fn kill_until_none(
    mut scan: impl FnMut() -> Option<Vec<i32>>,
    mut kill: impl FnMut(&[i32]),
    rounds: usize,
    pause: std::time::Duration,
) -> Result<()> {
    for _ in 0..rounds {
        let Some(pids) = scan() else {
            return Err(ManagerError::new("cannot enumerate build uid processes"));
        };
        if pids.is_empty() {
            return Ok(());
        }
        kill(&pids);
        std::thread::sleep(pause);
    }
    match scan() {
        Some(left) if left.is_empty() => Ok(()),
        Some(left) => Err(ManagerError::new(format!(
            "{} build uid processes survived the kill",
            left.len()
        ))),
        None => Err(ManagerError::new("cannot enumerate build uid processes")),
    }
}

#[cfg(test)]
mod tests {
    use super::{apply_build_limits, probe_ptrace_pid1};

    #[test]
    fn a_job_dir_that_cannot_be_unlinked_is_not_a_failure() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        let job = work.join("job-x");
        std::fs::create_dir_all(job.join("src")).unwrap();
        std::fs::write(job.join("src/a"), b"a").unwrap();
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o500)).unwrap();
        super::remove_job_tree(&job);
        assert!(
            !job.join("src").exists(),
            "build-owned contents are removed"
        );
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn kill_loop_succeeds_only_when_no_process_remains() {
        let pause = std::time::Duration::from_millis(1);
        let mut rounds = vec![vec![5, 6], vec![6], vec![]].into_iter();
        let mut killed = Vec::new();
        let ok = super::kill_until_none(
            || rounds.next(),
            |pids| killed.extend_from_slice(pids),
            10,
            pause,
        );
        assert!(ok.is_ok());
        assert_eq!(killed, [5, 6, 6]);

        let stuck = super::kill_until_none(|| Some(vec![9]), |_| {}, 3, pause);
        assert!(stuck.unwrap_err().to_string().contains("survived"));

        let blind = super::kill_until_none(|| None, |_| {}, 3, pause);
        assert!(blind.unwrap_err().to_string().contains("enumerate"));
    }

    #[test]
    fn new_session_is_entered_or_refused_for_a_group_leader() {
        match super::enter_new_session() {
            Ok(()) => {
                let pid = rustix::process::getpid();
                assert_eq!(rustix::process::getsid(None).unwrap(), pid);
                assert_eq!(rustix::process::getpgid(None).unwrap(), pid);
            }
            Err(err) => assert_eq!(err, rustix::io::Errno::PERM),
        }
    }

    #[test]
    fn build_limits_and_ptrace_probe_do_not_panic() {
        apply_build_limits();
        probe_ptrace_pid1();
    }
}
