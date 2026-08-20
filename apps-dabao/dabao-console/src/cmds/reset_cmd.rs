use crate::{CommonEnv, ShellCmdApi};

/// Console command that triggers a full SoC reboot via the `susres` (suspend/resume) service.
///
/// This is a genuine hardware reset -- it writes the reboot magic value into the system
/// controller's reset-control register (see `bao1x_hal::clocks::Clocks::reboot()`), which is
/// very different from toggling the USB CDC-ACM virtual DTR/RTS control lines: the Dabao SOM
/// implements its own native USB peripheral in firmware, and its CDC-ACM stack does not watch
/// for `SetControlLineState` changes, so a host-side DTR/RTS pulse has no effect on this
/// hardware. Going through `susres` is the only way to actually restart the chip from software.
pub struct ResetCmd {}
impl ResetCmd {
    pub fn new() -> Self { ResetCmd {} }
}

impl<'a> ShellCmdApi<'a> for ResetCmd {
    cmd_api!(reset);

    fn process(&mut self, _args: String, _env: &mut CommonEnv) -> Result<Option<String>, xous::Error> {
        println!("[reset] rebooting the SoC now...");
        let xns = xous_names::XousNames::new().unwrap();
        let susres = xous_api_susres::Susres::new_without_hook(&xns)
            .map_err(|_| xous::Error::InternalError)?;
        // `true` requests a whole-SoC reboot (as opposed to just the CPU, which would leave
        // peripherals such as the USB debug bridge in their current state).
        susres.reboot(true).ok();
        // the reboot takes effect asynchronously; if we're still alive momentarily, say so.
        Ok(None)
    }
}
