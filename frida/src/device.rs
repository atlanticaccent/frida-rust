/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use std::{
    any::Any,
    collections::{BTreeMap, HashMap},
    ffi::{CStr, CString},
    marker::PhantomData,
    ops::Deref,
    sync::{LazyLock, Mutex},
};

use frida_sys::{_FridaDevice, _GBytes};

use crate::{
    Error, Result, SpawnOptions, SpawnStdio, process::Process, session::Session, variant::Variant,
};

static ON_OUTPUT_HANDLER_DATA: LazyLock<Mutex<BTreeMap<usize, UserData>>> =
    LazyLock::new(|| Default::default());

/// Access to a Frida device.
pub struct Device<'a> {
    pub(crate) device_ptr: *mut _FridaDevice,
    phantom: PhantomData<&'a _FridaDevice>,

    on_output_handler_mappings: HashMap<std::ffi::c_ulong, usize>,
}

impl<'a> Device<'a> {
    pub(crate) fn from_raw(device_ptr: *mut _FridaDevice) -> Device<'a> {
        Device {
            device_ptr,
            phantom: PhantomData,

            on_output_handler_mappings: HashMap::new(),
        }
    }

    /// Returns the device's name.
    pub fn get_name(&self) -> &str {
        let name =
            unsafe { CStr::from_ptr(frida_sys::frida_device_get_name(self.device_ptr) as _) };
        name.to_str().unwrap_or_default()
    }

    /// Returns the device's id.
    pub fn get_id(&self) -> &str {
        let id = unsafe { CStr::from_ptr(frida_sys::frida_device_get_id(self.device_ptr) as _) };
        id.to_str().unwrap_or_default()
    }

    /// Returns the device's type
    ///
    /// # Example
    /// ```ignore
    ///# use frida::DeviceType;
    ///# let frida = unsafe { frida::Frida::obtain() };
    ///# let device_manager = frida::DeviceManager::obtain(&frida);
    ///# let device = device_manager.enumerate_all_devices().into_iter().find(|device| device.get_id() == "local").unwrap();
    /// assert_eq!(device.get_type(), DeviceType::Local);
    /// ```
    pub fn get_type(&self) -> DeviceType {
        unsafe { frida_sys::frida_device_get_dtype(self.device_ptr).into() }
    }

    /// Returns the device's system parameters
    ///
    /// # Example
    /// ```ignore
    ///# use std::collections::HashMap;
    ///# let frida = unsafe { frida::Frida::obtain() };
    ///# let device_manager = frida::DeviceManager::obtain(&frida);
    ///# let device = device_manager.enumerate_all_devices().into_iter().find(|device| device.get_id() == "local").unwrap();
    /// let params = device.query_system_parameters().unwrap();
    /// let os_version = params
    ///     .get("os")
    ///     .expect("No parameter \"os\" present")
    ///     .get_map()
    ///     .expect("Parameter \"os\" was not a mapping")
    ///     .get("version")
    ///     .expect("Parameter \"os\" did not contain a version field")
    ///     .get_string()
    ///     .expect("Version is not a string");
    /// ```
    pub fn query_system_parameters(&self) -> Result<HashMap<String, Variant>> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();

        let ht = unsafe {
            frida_sys::frida_device_query_system_parameters_sync(
                self.device_ptr,
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if !error.is_null() {
            let message = unsafe { CString::from_raw((*error).message) }
                .into_string()
                .map_err(|_| Error::CStringFailed)?;
            let code = unsafe { (*error).code };

            return Err(Error::DeviceQuerySystemParametersFailed { code, message });
        }

        let mut iter: frida_sys::GHashTableIter =
            unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        unsafe { frida_sys::g_hash_table_iter_init(&mut iter, ht) };
        let size = unsafe { frida_sys::g_hash_table_size(ht) };
        let mut map = HashMap::with_capacity(size as usize);

        let mut key = std::ptr::null_mut();
        let mut val = std::ptr::null_mut();
        while (unsafe { frida_sys::g_hash_table_iter_next(&mut iter, &mut key, &mut val) }
            != frida_sys::FALSE as i32)
        {
            let key = unsafe { CStr::from_ptr(key as _) };
            let val = unsafe { Variant::from_ptr(val as _) };
            map.insert(key.to_string_lossy().to_string(), val);
        }

        Ok(map)
    }

    /// Returns if the device is lost or not.
    pub fn is_lost(&self) -> bool {
        unsafe { frida_sys::frida_device_is_lost(self.device_ptr) == 1 }
    }

    /// Returns all processes (with [`Scope::Minimal`] — name + pid only).
    pub fn enumerate_processes<'b>(&'a self) -> Vec<Process<'b>>
    where
        'a: 'b,
    {
        self.enumerate_processes_with_options(Scope::Minimal)
    }

    /// Returns all processes, controlling how much metadata each one carries.
    ///
    /// With [`Scope::Full`] each returned [`Process`] populates
    /// [`Process::get_parameters`] (ppid, path, user, started, ...).
    pub fn enumerate_processes_with_options<'b>(&'a self, scope: Scope) -> Vec<Process<'b>>
    where
        'a: 'b,
    {
        let mut processes = Vec::new();
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();

        let opts = unsafe { frida_sys::frida_process_query_options_new() };
        unsafe {
            frida_sys::frida_process_query_options_set_scope(opts, scope as frida_sys::FridaScope);
        }

        let processes_ptr = unsafe {
            frida_sys::frida_device_enumerate_processes_sync(
                self.device_ptr,
                opts,
                std::ptr::null_mut(),
                &mut error,
            )
        };

        unsafe { frida_sys::frida_unref(opts as _) };

        if error.is_null() {
            let num_processes = unsafe { frida_sys::frida_process_list_size(processes_ptr) };
            processes.reserve(num_processes as usize);

            for i in 0..num_processes {
                let process_ptr = unsafe { frida_sys::frida_process_list_get(processes_ptr, i) };
                let process = Process::from_raw(process_ptr);
                processes.push(process);
            }
        }

        unsafe { frida_sys::frida_unref(processes_ptr as _) };
        processes
    }

    /// Creates [`Session`] and attaches the device to the current PID.
    pub fn attach<'b>(&'a self, pid: impl PidLike) -> Result<Session<'b>>
    where
        'a: 'b,
    {
        let pid = pid.into_u32();

        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        let session = unsafe {
            frida_sys::frida_device_attach_sync(
                self.device_ptr,
                pid,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if error.is_null() {
            Ok(Session::from_raw(session))
        } else {
            Err(Error::DeviceAttachError)
        }
    }

    /// Spawn a process on the device
    ///
    /// Returns the PID of the newly spawned process.
    /// On spawn, the process will be halted, and [`resume`](Device::resume) will need to be
    /// called to continue execution.
    pub fn spawn<S: AsRef<str>>(
        &mut self,
        program: S,
        options: &SpawnOptions,
    ) -> Result<SpawnedPid> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        let program = CString::new(program.as_ref()).unwrap();

        let pid = unsafe {
            frida_sys::frida_device_spawn_sync(
                self.device_ptr,
                program.as_ptr(),
                options.options_ptr,
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if !error.is_null() {
            let message = unsafe { CString::from_raw((*error).message) }
                .into_string()
                .map_err(|_| Error::CStringFailed)?;
            let code = unsafe { (*error).code };

            return Err(Error::SpawnFailed { code, message });
        }

        Ok(match options.spawn_stdio {
            SpawnStdio::Inherit => SpawnedPid::InheritedStdio(pid),
            SpawnStdio::Pipe => SpawnedPid::PipedStdio(pid),
        })
    }

    /// Resumes the process with given pid.
    pub fn resume(&self, pid: impl PidLike) -> Result<()> {
        let pid = pid.into_u32();
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe {
            frida_sys::frida_device_resume_sync(
                self.device_ptr,
                pid,
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if !error.is_null() {
            let message = unsafe { CString::from_raw((*error).message) }
                .into_string()
                .map_err(|_| Error::CStringFailed)?;
            let code = unsafe { (*error).code };

            return Err(Error::ResumeFailed { code, message });
        }

        Ok(())
    }

    /// Kill a process on the device
    pub fn kill(&mut self, pid: u32) -> Result<()> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe {
            frida_sys::frida_device_kill_sync(
                self.device_ptr,
                pid,
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if !error.is_null() {
            let message = unsafe { CString::from_raw((*error).message) }
                .into_string()
                .map_err(|_| Error::CStringFailed)?;
            let code = unsafe { (*error).code };

            return Err(Error::KillFailed { code, message });
        }

        Ok(())
    }

    ///
    pub fn on_output(&mut self, mut callback: impl FnMut(u32, i8, &[u8]) + Send + Sync + 'static) {
        self.on_output_with_context(move |pid, fd, data, _| callback(pid, fd, data), ());
    }

    ///
    pub fn on_output_with_context<
        Context: Any + Send + Sync,
        F: FnMut(u32, i8, &[u8], &mut Context) + Send + Sync + 'static,
    >(
        &mut self,
        mut callback: F,
        context: Context,
    ) {
        unsafe extern "C" fn on_output_impl(
            _device_ptr: *mut _FridaDevice,
            pid: u32,
            fd: i8,
            data: *const _GBytes,
            user_data_ptr: *mut std::ffi::c_void,
        ) {
            let shared_state_key = user_data_ptr as usize;
            let mut shared_handler_data = ON_OUTPUT_HANDLER_DATA
                .lock()
                .expect("Lock shared handler data for write");
            let Some(UserData { callback, context }) =
                shared_handler_data.get_mut(&shared_state_key)
            else {
                return;
            };

            let mut raw_data_size: frida_sys::gsize = 0;
            let raw_data = unsafe {
                frida_sys::g_bytes_get_data(data.cast_mut(), std::ptr::from_mut(&mut raw_data_size))
                    as *const u8
            };
            let data = if raw_data_size == 0 || raw_data.is_null() {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(raw_data, raw_data_size.try_into().unwrap()) }
            };

            callback(pid, fd, data, &mut **context as &mut dyn Any)
        }

        const OUTPUT_SIGNAL: *const std::ffi::c_char =
            unsafe { CStr::from_bytes_with_nul_unchecked(b"output\0").as_ptr() };

        let mut shared_handler_data = ON_OUTPUT_HANDLER_DATA
            .lock()
            .expect("Lock shared handler data for write");
        let key = shared_handler_data
            .last_key_value()
            .map(|(k, _)| k + 1)
            .unwrap_or(0);

        shared_handler_data.insert(
            key,
            UserData {
                callback: Box::new(move |pid, fd, data, context| {
                    callback(pid, fd, data, context.downcast_mut().unwrap())
                }),
                context: Box::new(context),
            },
        );

        let handler_id = unsafe {
            frida_sys::g_signal_connect_data(
                self.device_ptr as _,
                OUTPUT_SIGNAL,
                Some(std::mem::transmute(on_output_impl as *const ())),
                key as _,
                None,
                0,
            )
        };

        self.on_output_handler_mappings.insert(handler_id, key);
    }

    ///
    pub fn input(&self, pid: SpawnedPid, data: impl AsRef<[u8]>) -> Result<()> {
        let pid = match pid {
            SpawnedPid::InheritedStdio(pid) | SpawnedPid::Unknown(pid) => {
                return Err(Error::DeviceInputFailed {
                    pid,
                    code: None,
                    message: "process must be spawned with piped stdio".to_owned(),
                });
            }
            SpawnedPid::PipedStdio(pid) => pid,
        };

        let data = data.as_ref();
        let g_bytes =
            unsafe { frida_sys::g_bytes_new(data.as_ptr() as _, data.len().try_into().unwrap()) };
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();

        unsafe {
            frida_sys::frida_device_input_sync(
                self.device_ptr as _,
                pid,
                g_bytes,
                std::ptr::null_mut(),
                &raw mut error,
            )
        };

        if !error.is_null() {
            let message = unsafe { CString::from_raw((*error).message) }
                .into_string()
                .map_err(|_| Error::CStringFailed)?;
            let code = unsafe { (*error).code };

            return Err(Error::DeviceInputFailed {
                pid,
                code: Some(code),
                message,
            });
        }

        Ok(())
    }
}

impl Drop for Device<'_> {
    fn drop(&mut self) {
        let mut on_output_handler_data = ON_OUTPUT_HANDLER_DATA
            .lock()
            .expect("lock on_output handler data for cleanup");
        unsafe {
            for (handler_id, state_key) in &self.on_output_handler_mappings {
                frida_sys::g_signal_handler_disconnect(self.device_ptr as _, *handler_id);
                on_output_handler_data.remove(state_key);
            }

            frida_sys::frida_unref(self.device_ptr as _);
        };
    }
}

#[repr(u32)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
/// Frida device type.
///
/// Represents different connection types
// On Windows, the constants are i32 instead of u32, so we need to cast accordingly.
pub enum DeviceType {
    /// Local Frida device.
    Local = frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_LOCAL as _,

    /// Remote Frida device, connected via network
    Remote = frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_REMOTE as _,

    /// Device connected via USB
    USB = frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_USB as _,
}

#[cfg(not(target_family = "windows"))]
impl From<u32> for DeviceType {
    fn from(value: u32) -> Self {
        match value {
            frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_LOCAL => Self::Local,
            frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_REMOTE => Self::Remote,
            frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_USB => Self::USB,
            value => unreachable!("Invalid Device type {}", value),
        }
    }
}

#[cfg(target_family = "windows")]
impl From<i32> for DeviceType {
    fn from(value: i32) -> Self {
        match value {
            frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_LOCAL => Self::Local,
            frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_REMOTE => Self::Remote,
            frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_USB => Self::USB,
            value => unreachable!("Invalid Device type {}", value),
        }
    }
}

impl From<DeviceType> for frida_sys::FridaDeviceType {
    fn from(value: DeviceType) -> Self {
        match value {
            DeviceType::Local => frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_LOCAL,
            DeviceType::Remote => frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_REMOTE,
            DeviceType::USB => frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_USB,
        }
    }
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// How much metadata frida-core should attach to enumerated processes.
///
/// Maps to `FridaScope` in frida-core. `Minimal` is the default and only
/// fills `name` + `pid`; `Full` additionally populates
/// [`Process::get_parameters`].
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Name + pid only (frida-core default).
    Minimal = 0,
    /// Lightweight extras where the host platform supplies them cheaply.
    Metadata = 1,
    /// Includes parameters (ppid, path, user, started, ...).
    Full = 2,
}

struct UserData {
    callback: Box<dyn FnMut(u32, i8, &[u8], &mut dyn Any) + Send + Sync>,
    context: Box<dyn Any + Send + Sync>,
}

/// PID of a process spawned by calling [Device::spawn].
/// Primarily exists to ensure [Device::input] only targets processes spawned
/// by [Device::spawn] with stdio routing set to [SpawnStdio::Pipe].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnedPid {
    /// This process inherited its parent's stdio handles
    InheritedStdio(u32),
    /// This process is using pipes for stdio
    PipedStdio(u32),
    /// It's unknown how this process' stdio is being handled
    Unknown(u32),
}

impl Deref for SpawnedPid {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        match self {
            SpawnedPid::InheritedStdio(pid) => pid,
            SpawnedPid::PipedStdio(pid) => pid,
            SpawnedPid::Unknown(pid) => pid,
        }
    }
}

impl From<SpawnedPid> for u32 {
    fn from(value: SpawnedPid) -> Self {
        *value
    }
}

impl PartialEq<u32> for SpawnedPid {
    fn eq(&self, other: &u32) -> bool {
        **self == *other
    }
}

mod private {
    pub trait Sealed {}
}

/// Convenience trait to allow accepting _only_ plain [u32]s or [SpawnedPid]s.
pub trait PidLike: private::Sealed {
    ///
    fn into_u32(self) -> u32;
}

impl private::Sealed for u32 {}

impl PidLike for u32 {
    fn into_u32(self) -> u32 {
        self
    }
}

impl private::Sealed for SpawnedPid {}

impl PidLike for SpawnedPid {
    fn into_u32(self) -> u32 {
        *self
    }
}
