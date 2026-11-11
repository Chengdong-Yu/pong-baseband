/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef PONG_BASEBAND_22G100_H
#define PONG_BASEBAND_22G100_H

/* Native22G100 libIOABP/libPCITransport call sites retain selectors0..12
 * and three-word async references. These checks run before any narrowing,
 * user-memory mapping or queue transfer in the public bridge.
 * They do not publish hardware or acknowledge absent board operations.
 */
static IOReturn
pong_baseband22_validate(uint32_t selector, IOExternalMethodArguments *args)
{
    if (!args) return kIOReturnBadArgument;
    if (selector >= sizeof(cbh_interface_methods) / sizeof(cbh_interface_methods[0]))
        return kIOReturnUnsupported;
    const cbh_method &method = cbh_interface_methods[selector];
    if (args->scalarInputCount != method.scalars ||
        (method.scalars && !args->scalarInput)) return kIOReturnBadArgument;
    const bool async = args->asyncWakePort != MACH_PORT_NULL;
    if (async && (method.async_args == -1 || !args->asyncReference ||
                  args->asyncReferenceCount != CBH_ASYNC_REFERENCE_WORDS))
        return kIOReturnBadArgument;
    if (!async && args->asyncReferenceCount) return kIOReturnBadArgument;
    if (selector == 2 || selector == 3) {
        if (async) {
            const uint64_t address = args->scalarInput[0], length = args->scalarInput[1];
            if (!address || !length || length > BB_FRAME_MAX || address > UINT64_MAX - length)
                return kIOReturnBadArgument;
        } else {
            const uint64_t size = selector == 2 ?
                (args->structureInputDescriptor ? args->structureInputDescriptor->getLength() : args->structureInputSize) :
                (args->structureOutputDescriptor ? args->structureOutputDescriptor->getLength() : args->structureOutputSize);
            if (!size || size > BB_FRAME_MAX) return kIOReturnBadArgument;
        }
    }
    /* Source currently supplies no real shared-memory or time-event owner.
     * Do not inherit Coachz's successful no-op map/unmap registrations.
     * Keep these native selectors reserved for the eventual Pong backend.
     */
    if (selector >= 8) return kIOReturnUnsupported;
    return kIOReturnSuccess;
}
#endif
