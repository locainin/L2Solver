use super::*;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};

// Keep private descriptor checks beside the integration tests, without exposing raw handles
#[test]
fn frontend_controller_clones_close_exec() -> Result<(), Box<dyn std::error::Error>> {
    let (frontend, helper) = local_transport_pair()?;
    let cloned = frontend.try_clone()?;
    let control = helper.clone_control()?;
    for socket in [&cloned.data, &cloned.control, &control] {
        let flags = FdFlag::from_bits_truncate(fcntl(&socket.fd, FcntlArg::F_GETFD)?);
        assert!(flags.contains(FdFlag::FD_CLOEXEC));
    }
    Ok(())
}

#[test]
fn reusable_receive_buffer_lengths_bounds() -> Result<(), Box<dyn std::error::Error>> {
    let (frontend, helper) = local_transport_pair()?;
    let mut buffer = [0; 8];
    assert!(matches!(
        frontend.try_recv_into(false, &mut buffer),
        Err(TransportError::WouldBlock)
    ));
    helper.try_send_data(&[1, 2, 3])?;
    let length = frontend.try_recv_into(false, &mut buffer)?;
    assert_eq!(buffer.get(..length), Some([1, 2, 3].as_slice()));
    helper.try_send_data(&[4])?;
    let length = frontend.try_recv_into(false, &mut buffer)?;
    assert_eq!(buffer.get(..length), Some([4].as_slice()));
    helper.try_send_data(&[5; 9])?;
    assert!(matches!(
        frontend.try_recv_into(false, &mut buffer),
        Err(TransportError::MessageTooLarge {
            length: 9,
            maximum: 8
        })
    ));
    assert!(matches!(
        frontend.try_recv_into(false, &mut buffer),
        Err(TransportError::WouldBlock)
    ));
    helper.control.try_send(&[6])?;
    let length = frontend.try_recv_into(true, &mut buffer)?;
    assert_eq!(buffer.get(..length), Some([6].as_slice()));
    Ok(())
}
