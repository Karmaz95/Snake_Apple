#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/mach_error.h>
#include <mach/task_special_ports.h>
#include <stdio.h>
#include <stdlib.h>

const char* get_special_port_name(int port_id) {
  switch (port_id) {
      case TASK_KERNEL_PORT:
          return "TASK_KERNEL_PORT";
      case TASK_HOST_PORT:
          return "TASK_HOST_PORT";
      case TASK_NAME_PORT:
          return "TASK_NAME_PORT";
      case TASK_BOOTSTRAP_PORT:
          return "TASK_BOOTSTRAP_PORT";
      case TASK_INSPECT_PORT:
          return "TASK_INSPECT_PORT";
      case TASK_READ_PORT:
          return "TASK_READ_PORT";
      case TASK_ACCESS_PORT:
          return "TASK_ACCESS_PORT";
      case TASK_DEBUG_CONTROL_PORT:
          return "TASK_DEBUG_CONTROL_PORT";
      case TASK_RESOURCE_NOTIFY_PORT:
          return "TASK_RESOURCE_NOTIFY_PORT";
      default:
          return "UNKNOWN_PORT";
  }
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
      printf("Usage: %s <pid>\n", argv[0]);
      return 1;
  }

  pid_t pid = atoi(argv[1]);
  task_t task;
  kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
  
  if (kr != KERN_SUCCESS) {
      printf("Failed to get task for pid %d: %s (0x%x)\n", 
             pid, mach_error_string(kr), kr);
      return 1;
  }
  
  int special_ports[] = {
      TASK_KERNEL_PORT,
      TASK_HOST_PORT,
      TASK_NAME_PORT,
      TASK_BOOTSTRAP_PORT,
      TASK_INSPECT_PORT,
      TASK_READ_PORT,
      TASK_ACCESS_PORT,
      TASK_DEBUG_CONTROL_PORT,
      TASK_RESOURCE_NOTIFY_PORT
  };
  
  int num_ports = sizeof(special_ports) / sizeof(special_ports[0]);
  
  printf("Listing Special Ports for PID %d (1 to %d):\n", pid, TASK_MAX_SPECIAL_PORT);
  printf("================================\n");
  
  for (int i = 0; i < num_ports; i++) {
      mach_port_t special_port;
      kr = task_get_special_port(task, special_ports[i], &special_port);
      
      printf("Port %d (%s):\n", special_ports[i], get_special_port_name(special_ports[i]));
      printf("  Status: %s\n", kr == KERN_SUCCESS ? "SUCCESS" : "FAILED");
      
      if (kr != KERN_SUCCESS) {
          printf("  Error: %s (0x%x)\n", mach_error_string(kr), kr);
      } else {
          printf("  Port number: 0x%x\n", special_port);
          
          mach_port_type_t port_type;
          kr = mach_port_type(task, special_port, &port_type);
          if (kr == KERN_SUCCESS) {
              printf("  Rights: ");
              if (port_type & MACH_PORT_TYPE_SEND)
                  printf("SEND ");
              if (port_type & MACH_PORT_TYPE_RECEIVE)
                  printf("RECEIVE ");
              if (port_type & MACH_PORT_TYPE_SEND_ONCE)
                  printf("SEND_ONCE ");
              if (port_type & MACH_PORT_TYPE_PORT_SET)
                  printf("PORT_SET ");
              if (port_type & MACH_PORT_TYPE_DEAD_NAME)
                  printf("DEAD_NAME ");
              printf("\n");
          }
      }
      printf("\n");
  }

  mach_port_deallocate(mach_task_self(), task);
  return 0;
}
