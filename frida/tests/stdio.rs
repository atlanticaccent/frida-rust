use std::{
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
                if pid == target_pid {
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

    let mut iterations = 1;
    while device
        .enumerate_processes()
        .into_iter()
        .any(|process| process.get_pid() == target_pid)
    {
        sleep(Duration::from_millis(100 * iterations));
        assert!(iterations <= 50);
        iterations += 1
    }

    assert!(saw_startup.load(std::sync::atomic::Ordering::Relaxed));
    assert!(!saw_shutdown.load(std::sync::atomic::Ordering::Relaxed));
}
