// gcc -o port_inspector port_inspector.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/mach_error.h>

void print_port_info(task_t task, mach_port_name_t port_name) {
    mach_port_status_t status;
    mach_msg_type_number_t status_count = MACH_PORT_RECEIVE_STATUS_COUNT;
    kern_return_t kr;

    kr = mach_port_get_attributes(task,
                                 port_name,
                                 MACH_PORT_RECEIVE_STATUS,
                                 (mach_port_info_t)&status,
                                 &status_count);

    if (kr == KERN_SUCCESS) {
        printf("    Queue size: %d\n", status.mps_msgcount);
        printf("    Max queue size: %d\n", status.mps_qlimit);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    task_t target_task;
    pid_t pid = atoi(argv[1]);

    kern_return_t kr = task_for_pid(mach_task_self(), pid, &target_task);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get task for pid %d: %s\n", pid, mach_error_string(kr));
        return 1;
    }

    // Get task basic info
    task_basic_info_data_t basic_info;
    mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
    kr = task_info(target_task, TASK_BASIC_INFO, (task_info_t)&basic_info, &count);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get task info: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), target_task);
        return 1;
    }

    // Get port info
    ipc_info_space_t space_info;
    ipc_info_name_array_t table;
    mach_msg_type_number_t table_count;
    ipc_info_tree_name_array_t tree;
    mach_msg_type_number_t tree_count;

    kr = mach_port_space_info(target_task, &space_info, &table, &table_count, &tree, &tree_count);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get port space info: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), target_task);
        return 1;
    }

    printf("\nProcess %d Port Space Information:\n", pid);
    printf("Total ports: %d\n", table_count);
    printf("Space generation number mask: 0x%x\n\n", space_info.iis_genno_mask);

    // Print information about each port
    for (mach_msg_type_number_t i = 0; i < table_count; i++) {
        if (table[i].iin_type != MACH_PORT_TYPE_NONE) {
            printf("Port %d:\n", i);
            printf("  Name: 0x%x\n", table[i].iin_name);
            printf("  Type: 0x%x (", table[i].iin_type);

            // Decode port type
            if (table[i].iin_type & MACH_PORT_TYPE_SEND)
                printf("SEND ");
            if (table[i].iin_type & MACH_PORT_TYPE_RECEIVE)
                printf("RECEIVE ");
            if (table[i].iin_type & MACH_PORT_TYPE_SEND_ONCE)
                printf("SEND_ONCE ");
            if (table[i].iin_type & MACH_PORT_TYPE_PORT_SET)
                printf("PORT_SET ");
            if (table[i].iin_type & MACH_PORT_TYPE_DEAD_NAME)
                printf("DEAD_NAME ");
            printf(")\n");

            printf("  User References: %d\n", table[i].iin_urefs);

            // Get additional port info for RECEIVE rights
            if (table[i].iin_type & MACH_PORT_TYPE_RECEIVE) {
                print_port_info(target_task, table[i].iin_name);
            }
            printf("\n");
        }
    }

    // Cleanup
    vm_deallocate(mach_task_self(), (vm_address_t)table, 
                 table_count * sizeof(ipc_info_name_t));
    vm_deallocate(mach_task_self(), (vm_address_t)tree, 
                 tree_count * sizeof(ipc_info_tree_name_t));
    mach_port_deallocate(mach_task_self(), target_task);

    return 0;
}