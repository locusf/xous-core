use usb_device::class_prelude::*;
use usb_device::{Result, UsbError};

const USB_CLASS_VENDOR_SPEC: u8 = 0xff;
const CHAOSKEY_PACKET_SIZE: usize = 64;

pub struct HwrngPort<'a, B: UsbBus> {
    interface: InterfaceNumber,
    write_ep: EndpointIn<'a, B>,
}

impl<'a, B: UsbBus> HwrngPort<'a, B> {
    pub fn new(alloc: &'a UsbBusAllocator<B>, max_packet_size: u16) -> Self {
        HwrngPort { interface: alloc.interface(), write_ep: alloc.bulk(max_packet_size) }
    }

    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        self.write_ep.write(&data[..data.len().min(CHAOSKEY_PACKET_SIZE)])
    }

    pub fn read(&mut self, _data: &mut [u8]) -> Result<usize> {
        Err(UsbError::WouldBlock)
    }

    pub fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<B: UsbBus> UsbClass<B> for HwrngPort<'_, B> {
    fn get_configuration_descriptors(&self, writer: &mut DescriptorWriter) -> Result<()> {
        writer.interface(self.interface, USB_CLASS_VENDOR_SPEC, 0, 0)?;
        writer.endpoint(&self.write_ep)?;
        Ok(())
    }
}
