use std::{
    io::{BufRead, Read},
    sync::{Arc, LazyLock, atomic::AtomicBool},
    thread::sleep,
    time::Duration,
};

use frida::{DeviceManager, Frida, SpawnOptions};

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

#[test]
#[ignore]
fn stdout_fixture() {
    eprintln!("startup");
    for n in 0..10 {
        eprintln!("{}", n.to_string().repeat(n + 1));
        sleep(Duration::from_millis(20));
    }
    eprintln!("shutdown");
}

#[test]
#[ignore]
fn stdin_fixture() {
    let mut buffer = String::new();
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();

    handle.read_line(&mut buffer).expect("read input");
    let buffer = buffer.trim();

    eprintln!("{buffer}");
    std::fs::write(buffer, buffer.len().to_string())
        .expect("assume input is file path and write input length to new file at path");
}

#[test]
fn test_on_output_handler() {
    let dm = DeviceManager::obtain(&FRIDA);
    let mut device = dm
        .get_local_device()
        .expect("local device should be available");

    let executable = std::env::current_exe()
        .expect("get current executable aka test executable")
        .display()
        .to_string();

    let target_pid = device
        .spawn(
            &executable,
            &SpawnOptions::new()
                .argv([
                    &executable,
                    "stdout_fixture",
                    "--exact",
                    "--nocapture",
                    "--ignored",
                ])
                .stdio(frida::SpawnStdio::Pipe),
        )
        .expect("spawn test");

    let saw_startup = Arc::new(AtomicBool::new(false));
    let saw_shutdown = Arc::new(AtomicBool::new(false));

    device.on_output_with_context(
        {
            let saw_startup = Arc::clone(&saw_startup);
            let saw_shutdown = Arc::clone(&saw_shutdown);
            move |pid, _, data, _context| {
                let thread = std::thread::current();
                eprintln!(
                    "thread_id={:?} | thread_name={:?} | pid={pid}: \"{}\"",
                    thread.id(),
                    thread.name(),
                    str::from_utf8(data).unwrap()
                );
                if target_pid == pid {
                    let output = str::from_utf8(data).unwrap().trim();
                    if output == "startup" {
                        saw_startup.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    if output == "shutdown" {
                        saw_shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        },
        (),
    );

    device.resume(target_pid).expect("resume spawned test");

    sleep(Duration::from_millis(80));

    drop(device);

    let device = dm.get_local_device().expect("get new local device");

    poll_process_termination(device, target_pid);

    assert!(saw_startup.load(std::sync::atomic::Ordering::Relaxed));
    assert!(!saw_shutdown.load(std::sync::atomic::Ordering::Relaxed));
}

#[test]
fn test_write_stdin() {
    let dm = DeviceManager::obtain(&FRIDA);
    let mut device = dm
        .get_local_device()
        .expect("local device should be available");

    let executable = std::env::current_exe()
        .expect("get current executable aka test executable")
        .display()
        .to_string();

    let target_pid = device
        .spawn(
            &executable,
            &SpawnOptions::new()
                .argv([
                    &executable,
                    "stdin_fixture",
                    "--exact",
                    "--nocapture",
                    "--ignored",
                ])
                .stdio(frida::SpawnStdio::Pipe),
        )
        .expect("spawn test");

    // device.on_output(|pid, _fd, output| eprintln!("{pid}: {}", str::from_utf8(output).unwrap()));

    let (mut file, path) = tempfile::NamedTempFile::new()
        .expect("create named temp file")
        .into_parts();

    device.resume(target_pid).expect("resume spawned test");

    device
        .input(target_pid, format!("{}\n", path.display()))
        .expect("write to target process stdin");

    poll_process_termination(device, target_pid);

    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .expect("read contents of temp file");

    assert_eq!(path.display().to_string().len().to_string(), buf)
}

fn poll_process_termination(device: frida::Device<'_>, target_pid: frida::SpawnedPid) {
    const MAX_RETRIES: u32 = 50;

    let mut iterations = 1;
    while device
        .enumerate_processes()
        .into_iter()
        .any(|process| target_pid == process.get_pid())
    {
        sleep(Duration::from_millis(10 * 2_u64.pow(iterations)));
        assert!(
            iterations <= MAX_RETRIES,
            "process {} still running after {MAX_RETRIES} retries",
            *target_pid
        );
        iterations += 1
    }
}
