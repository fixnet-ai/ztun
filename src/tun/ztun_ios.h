/// ztun_ios.h - C interface for iOS Network Extension integration
///
/// This header provides a C API for integrating ztun with iOS
/// NEPacketTunnelProvider. Since iOS doesn't expose TUN/UTUN file
/// descriptors directly, this API uses callback-based packet I/O.
///
/// Usage:
/// 1. In Swift PacketTunnelProvider, implement readPacket/writePacket
/// 2. Call ztun_ios_create() with callbacks
/// 3. Call ztun_ios_recv()/ztun_ios_send() for packet operations
/// 4. Call ztun_ios_destroy() when done

#ifndef ZTUN_IOS_H
#define ZTUN_IOS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Opaque handle to ztun iOS device
typedef struct ztun_ios_device ztun_ios_device_t;

/// Read packet callback
/// Called by ztun to receive packets from the VPN tunnel
/// Returns: number of bytes read, or -1 on error
typedef int32_t (*ztun_read_packet_fn)(
    void* context,
    uint8_t* buffer,
    int32_t buffer_size
);

/// Write packet callback
/// Called by ztun to send packets to the VPN tunnel
/// Returns: number of bytes written, or -1 on error
typedef int32_t (*ztun_write_packet_fn)(
    void* context,
    const uint8_t* packet,
    int32_t packet_size
);

/// Create a ztun device for iOS from packet flow callbacks
///
/// @param context          Opaque context passed to callbacks
/// @param read_fn         Callback to read packets from tunnel
/// @param write_fn        Callback to write packets to tunnel
/// @param mtu             Maximum transmission unit (typically 1500)
///
/// @return                Opaque device handle, or NULL on error
ztun_ios_device_t* ztun_ios_create(
    void* context,
    ztun_read_packet_fn read_fn,
    ztun_write_packet_fn write_fn,
    uint16_t mtu
);

/// Receive a packet from the VPN tunnel
///
/// @param device          Device handle from ztun_ios_create()
/// @param buffer          Buffer to receive packet data
/// @param buffer_size     Size of buffer
///
/// @return                Number of bytes read, or -1 on error
int32_t ztun_ios_recv(
    ztun_ios_device_t* device,
    uint8_t* buffer,
    int32_t buffer_size
);

/// Send a packet to the VPN tunnel
///
/// @param device          Device handle from ztun_ios_create()
/// @param packet          Packet data to send
/// @param packet_size     Size of packet data
///
/// @return                Number of bytes sent, or -1 on error
int32_t ztun_ios_send(
    ztun_ios_device_t* device,
    const uint8_t* packet,
    int32_t packet_size
);

/// Get the MTU of the device
///
/// @param device          Device handle from ztun_ios_create()
///
/// @return                MTU value
uint16_t ztun_ios_get_mtu(ztun_ios_device_t* device);

/// Destroy the device and clean up resources
///
/// @param device          Device handle from ztun_ios_create()
void ztun_ios_destroy(ztun_ios_device_t* device);

#ifdef __cplusplus
}
#endif

#endif // ZTUN_IOS_H
