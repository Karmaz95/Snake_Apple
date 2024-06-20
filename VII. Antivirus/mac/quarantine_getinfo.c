__int64 __fastcall quarantine_getinfo(
        struct vnode *node,        // a1: vnode object representing the file
        char *buffer,              // a2: buffer to store quarantine info
        size_t *buffer_size,       // a3: size of the buffer
        int flag,                  // a4: flag to determine the operation mode
        __int64 reserved1,         // a5: reserved, not used in this function
        __int64 reserved2,         // a6: reserved, not used in this function
        __int64 reserved3,         // a7: reserved, not used in this function
        __int64 reserved4,         // a8: reserved, not used in this function
        __int64 reserved5,         // a9: reserved, not used in this function
        size_t max_size)           // a10: maximum allowed size for the buffer
{
  // Local variables
  size_t initial_buffer_size = *buffer_size;  // Initial size of the buffer
  __int64 attr_length = 0LL;                  // Attribute length placeholder
  struct mount *mount_info;                   // Mount information
  int result;                                 // Result of operations

  mount_info = vnode_mount(node);
  if (flag) {
    if (vnode_isvroot(node)) {
      if ((vfs_flags(mount_info) & 0x400) == 0) {
        return 93LL;  // Return 93 if the file system does not have the required flag
      }
      if (vnode_isvroot(node)) {
        if ((vfs_flags(mount_info) & 0x400) != 0) {
          goto LABEL_11;
        }
        return 93LL;  // Return 93 if the file system does not have the required flag
      }
    }
    return 22LL;  // Return 22 if the vnode is not the root
  }

  if ((vfs_flags(mount_info) & 0x400) == 0) {
    result = mac_vnop_getxattr(node, "com.apple.quarantine", buffer, initial_buffer_size, &attr_length);
    if ((unsigned int)result <= 0x2D) {
      if (((1LL << result) & 0x200000402002LL) != 0) {
        return 93LL;  // Return 93 if the result is in the specific error range
      }
      if (!(_DWORD)result) {
        if (attr_length <= initial_buffer_size) {
          result = 0LL;
          *buffer_size = attr_length;
          return result;  // Return 0 on success
        }
        return 34LL;  // Return 34 if the buffer is too small
      }
    }
    if ((_DWORD)result != 102) {
      return result;  // Return the result if it is not 102
    }
    return 93LL;  // Return 93 for specific error
  }

LABEL_11:
  if (!vfs_mntlabel(mount_info) || (const char *mount_label = (const char *)mount_label_copy_quarantine_info()) == 0LL) {
    size_t default_info_len = strlen(quarantine_getinfo_default_qtninfo);
    if (default_info_len <= initial_buffer_size) {
      *buffer_size = default_info_len;
      memmove(buffer, quarantine_getinfo_default_qtninfo, default_info_len);
      return 0LL;  // Return 0 on success with default info
    }
    return 34LL;  // Return 34 if the buffer is too small for default info
  }

  size_t mount_label_len = strlen(mount_label);
  if (mount_label_len <= initial_buffer_size) {
    *buffer_size = mount_label_len;
    memmove(buffer, mount_label, mount_label_len);
    result = 0LL;  // Return 0 on success
  } else {
    result = 34LL;  // Return 34 if the buffer is too small for mount label
  }
  kfree_data_addr_external(mount_label);
  return result;
}