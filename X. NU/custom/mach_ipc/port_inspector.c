#include <stdio.h>
#include <mach/mach.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
   if (argc != 2) {
       printf("Usage: %s <pid>\n", argv[0]);
       return 1;
   }

   pid_t target_pid = atoi(argv[1]);
   kern_return_t kr;
   mach_port_t task;
   
   kr = task_for_pid(mach_task_self(), target_pid, &task);
   if (kr != KERN_SUCCESS) {
       printf("Failed to get task for pid %d: %s\n", target_pid, mach_error_string(kr));
       return 1;
   }

   ipc_info_name_array_t table_info;
   mach_msg_type_number_t table_infoCnt;
   ipc_info_tree_name_array_t tree_info;
   mach_msg_type_number_t tree_infoCnt;
   ipc_info_space_t space_info;

   kr = mach_port_space_info(task, &space_info, &table_info, &table_infoCnt, &tree_info, &tree_infoCnt);
   if (kr != KERN_SUCCESS) {
       printf("Failed to get port space info: %s\n", mach_error_string(kr));
       return 1;
   }

   printf("IPC Space Info:\n");
   printf("Table size: %d, Next: %d, Active ports: %d\n\n", 
          space_info.iis_table_size, space_info.iis_table_next, table_infoCnt);

   printf("%-6s | %-6s | %-20s | %-4s | %-10s\n", 
          "Index", "Name", "Rights", "Refs", "Generation");
   printf("-------------------------------------------------------------------\n");

   for (int i = 0; i < table_infoCnt; i++) {
       char rights[32] = "";
       if (table_info[i].iin_type & MACH_PORT_TYPE_RECEIVE) strcat(rights, "RECV ");
       if (table_info[i].iin_type & MACH_PORT_TYPE_SEND) strcat(rights, "SEND ");
       if (table_info[i].iin_type & MACH_PORT_TYPE_SEND_ONCE) strcat(rights, "ONCE ");
       if (table_info[i].iin_type & MACH_PORT_TYPE_PORT_SET) strcat(rights, "SET ");
       if (table_info[i].iin_type & MACH_PORT_TYPE_DEAD_NAME) strcat(rights, "DEAD ");
       if (rights[0] == '\0') strcpy(rights, "IO_NULL");

       printf("%-6d | 0x%-4x | %-20s | %-4d | %-10d\n",
              i,
              table_info[i].iin_name,
              rights,
              table_info[i].iin_urefs,
              MACH_PORT_INDEX(table_info[i].iin_name) >> 24);
   }

   mach_port_deallocate(mach_task_self(), task);
   vm_deallocate(mach_task_self(), (vm_address_t)table_info, table_infoCnt * sizeof(*table_info));
   vm_deallocate(mach_task_self(), (vm_address_t)tree_info, tree_infoCnt * sizeof(*tree_info));
   return 0;
}