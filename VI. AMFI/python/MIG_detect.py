# The script is not mine. Here is the source: https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py

# This script attempts to identify mach_port_subsystem structures in the
# __DATA section of executables or kernels
#
# const struct mach_port_subsystem {
#     mig_server_routine_t      server;         /* Server routine */
#     mach_msg_id_t             start;          /* Min routine number */
#     mach_msg_id_t             end;            /* Max routine number + 1 */
#     unsigned int              maxsize;        /* Max msg size */
#     vm_address_t              reserved;       /* Reserved */
#     struct routine_descriptor routine[X];     /* Array of routine descriptors */
# }
#
# struct routine_descriptor {
#     mig_impl_routine_t        impl_routine;   /* Server work func pointer   */
#     mig_stub_routine_t        stub_routine;   /* Unmarshalling func pointer */
#     unsigned int              argc;           /* Number of argument words   */
#     unsigned int              descr_count;    /* Number complex descriptors */
#     routine_arg_descriptor_t  arg_descr;      /* pointer to descriptor array*/
#     unsigned int              max_reply_msg;  /* Max size for reply msg     */
# };
#
# If it finds the mach_port_subsystem structure then it will label the structure as 
# well as labelling each MIG msg stub function.

sections = [
    ('__DATA', '__const'),
    ('__CONST', '__constdata'),
    ('__DATA_CONST', '__const'),
]

doc = Document.getCurrentDocument()

for (segname, secname) in sections:
    seg = doc.getSegmentByName(segname)

    if seg is None:
        continue

    seclist = seg.getSectionsList()
    for sec in seclist:
        if sec.getName() != secname:
            continue

        # Loop through each item in the section
        start = sec.getStartingAddress()
        end = start + sec.getLength() - 0x28

        for addr in range(start, end):            
            mach_port_subsystem_reserved = seg.readUInt64LE(addr + 0x18)
            mach_port_subsystem_routine0_impl_routine = seg.readUInt64LE(addr + 0x20)
            mach_port_subsystem_start = seg.readUInt32LE(addr + 0x8)
            mach_port_subsystem_end = seg.readUInt32LE(addr + 0xc)
            number_of_msgs = mach_port_subsystem_end - mach_port_subsystem_start

            # Check if this looks like a mach_port_subsystem structure
            if (mach_port_subsystem_reserved == 0 and
                mach_port_subsystem_routine0_impl_routine == 0 and
                mach_port_subsystem_start != 0 and
                number_of_msgs > 0 and
                number_of_msgs < 1024):
                subsystem_name = "_MIG_subsystem_{0}".format(mach_port_subsystem_start)
                doc.log("{0}: MIG Subsystem {1}: {2} messages".format(hex(addr), mach_port_subsystem_start, number_of_msgs))
                seg.setNameAtAddress(addr, subsystem_name)

                # Loop through the routine_descriptor structs
                msg_num = 0
                for routine_addr in range(addr + 0x20, addr+0x20+(number_of_msgs*0x28), 0x28):
                    stub_routine_addr = routine_addr + 0x8
                    stub_routine = seg.readUInt64LE(stub_routine_addr)
                    msg = mach_port_subsystem_start + msg_num

                    if stub_routine == 0:
                        doc.log("{0}: skip MIG msg {1}".format(hex(stub_routine_addr), msg))
                    else:
                        routine_name = "_MIG_msg_{0}".format(msg)
                        doc.log("{0}: MIG msg {1}".format(hex(stub_routine_addr), msg))
                        doc.setNameAtAddress(stub_routine, routine_name)

                    msg_num = msg_num + 1
