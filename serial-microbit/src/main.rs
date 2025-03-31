#![no_std]
#![no_main]

use defmt::*;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::select::select;
use embassy_nrf::{self, bind_interrupts, interrupt, peripherals, uarte};
use embedded_alloc::LlffHeap as Heap;
use nrf_softdevice::{
    ble::{
        self,
        peripheral::{self, AdvertiseError},
    },
    raw, Softdevice,
};
use panic_probe as _;

#[global_allocator]
static HEAP: Heap = Heap::empty();

const NAME: &[u8] = b"serial_needle\0";
const NAME_LEN: u16 = NAME.len() as u16;

#[embassy_executor::task]
async fn softdevice_task(sd: &'static Softdevice) -> ! {
    sd.run().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    {
        use core::mem::MaybeUninit;
        const HEAP_SIZE: usize = 1024;
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { HEAP.init(&raw mut HEAP_MEM as usize, HEAP_SIZE) }
    }

    let mut config = embassy_nrf::config::Config::default();
    config.time_interrupt_priority = interrupt::Priority::P2;
    let p = embassy_nrf::init(config);

    let config = nrf_softdevice::Config {
        clock: Some(raw::nrf_clock_lf_cfg_t {
            source: raw::NRF_CLOCK_LF_SRC_RC as u8,
            rc_ctiv: 16,
            rc_temp_ctiv: 2,
            accuracy: raw::NRF_CLOCK_LF_ACCURACY_500_PPM as u8,
        }),
        conn_gap: Some(raw::ble_gap_conn_cfg_t {
            conn_count: 1,
            event_length: 24,
        }),
        conn_gatt: Some(raw::ble_gatt_conn_cfg_t { att_mtu: 256 }),
        gatts_attr_tab_size: Some(raw::ble_gatts_cfg_attr_tab_size_t {
            attr_tab_size: raw::BLE_GATTS_ATTR_TAB_SIZE_DEFAULT,
        }),
        gap_role_count: Some(raw::ble_gap_cfg_role_count_t {
            adv_set_count: 1,
            periph_role_count: 3,
            central_role_count: 3,
            central_sec_count: 0,
            _bitfield_1: raw::ble_gap_cfg_role_count_t::new_bitfield_1(0),
        }),
        gap_device_name: Some(raw::ble_gap_cfg_device_name_t {
            p_value: NAME.as_ptr() as _,
            current_len: NAME_LEN,
            max_len: NAME_LEN,
            write_perm: raw::ble_gap_conn_sec_mode_t {
                // disable write permissions
                _bitfield_1: raw::ble_gap_conn_sec_mode_t::new_bitfield_1(0, 0),
            },
            _bitfield_1: raw::ble_gap_cfg_device_name_t::new_bitfield_1(
                raw::BLE_GATTS_VLOC_USER as u8,
            ),
        }),
        ..Default::default()
    };

    bind_interrupts!(struct Irqs {
       UARTE0_UART0 => uarte::InterruptHandler<peripherals::UARTE0>;
    });
    let sd = Softdevice::enable(&config);
    unwrap!(spawner.spawn(softdevice_task(sd)));

    let mut config = uarte::Config::default();
    config.parity = uarte::Parity::EXCLUDED;
    config.baudrate = uarte::Baudrate::BAUD115200;
    let mut uart = uarte::Uarte::new(p.UARTE0, Irqs, p.P1_08, p.P0_06, config);

    let mut buf = [0u8; 37];
    unwrap!(uart.read(&mut buf).await);
    loop {
        info!("read new advertisement");

        let adv_fut = broadcast_advertisement(sd, buf);
        let read_fut = uart.read(&mut buf);
        select(adv_fut, read_fut).await;

        info!("returned from select");
    }
}

async fn broadcast_advertisement(sd: &Softdevice, data: [u8; 37]) -> Result<(), AdvertiseError> {
    let config = peripheral::Config {
        interval: 1000,
        ..Default::default()
    };

    let mut ble_addr_le = [0u8; 6];
    ble_addr_le.copy_from_slice(&data[0..6]);
    ble_addr_le.reverse();

    ble::set_address(
        sd,
        &ble::Address::new(ble::AddressType::Public, ble_addr_le),
    );
    let adv = peripheral::NonconnectableAdvertisement::NonscannableUndirected {
        adv_data: &data[6..],
    };

    peripheral::advertise(sd, adv, &config).await
}
