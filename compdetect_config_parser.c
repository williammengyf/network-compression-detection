/* Parser of the config file  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "compdetect_config_parser.h"

/* Parse a JSON entry and update the config struct.  */
void
parse_json_entry (const char *start, const char *end, struct compdetect_config *config)
{
  int entry_len = end - start;
  char entry[entry_len + 1];
  strncpy (entry, start, end - start);
  entry[end - start] = '\0';
  if (strstr (entry, "server_ip_addr"))
    {
      sscanf (entry, " \"server_ip_addr\": \"%[^\"]\"", config->server_ip_addr);
    }
  if (strstr (entry, "standalone_ip_addr"))
    {
      sscanf (entry, " \"standalone_ip_addr\": \"%[^\"]\"", config->standalone_ip_addr);
    }
  else if (strstr (entry, "udp_src_port"))
    {
      sscanf (entry, " \"udp_src_port\": %d", &config->udp_src_port);
    }
  else if (strstr (entry, "udp_dest_port"))
    {
      sscanf (entry, " \"udp_dest_port\": %d", &config->udp_dest_port);
    }
  else if (strstr (entry, "tcp_head_syn_dest_port"))
    {
      sscanf (entry, " \"tcp_head_syn_dest_port\": %d", &config->tcp_head_syn_dest_port);
    }
  else if (strstr (entry, "tcp_tail_syn_dest_port"))
    {
      sscanf (entry, " \"tcp_tail_syn_dest_port\": %d", &config->tcp_tail_syn_dest_port);
    }
  else if (strstr (entry, "tcp_dest_port"))
    {
      sscanf (entry, " \"tcp_dest_port\": %d", &config->tcp_dest_port);
    }
  else if (strstr (entry, "udp_payload_size"))
    {
      sscanf (entry, " \"udp_payload_size\": %d", &config->udp_payload_size);
    }
  else if (strstr (entry, "inter_measurement_time"))
    {
      sscanf (entry, " \"inter_measurement_time\": %d", &config->inter_measurement_time);
    }
  else if (strstr (entry, "udp_packet_count"))
    {
      sscanf (entry, " \"udp_packet_count\": %d", &config->udp_packet_count);
    }
  else if (strstr (entry, "udp_packet_ttl"))
    {
      sscanf (entry, " \"udp_packet_ttl\": %d", &config->udp_packet_ttl);
    }
}

/* Parse a JSON string and return the result in a config struct.  */
struct compdetect_config *
parse_json_string (const char *json_str)
{
  struct compdetect_config *config = calloc (1, sizeof (struct compdetect_config));
  if (!config)
    {
      perror ("cannot allocate memory");
      return NULL;
    }

  char line[256];
  const char *start = json_str;
  const char *end;

  if (*start == '{')
    {
      start++;
    }

  while ((end = strchr (start, ':')))
    {
      const char *comma = strchr (start, ',');

      if (!comma)
        {
          comma = strchr (start, '}');
        }

      if (comma && comma > end)
        {
          end = comma;
          parse_json_entry (start, end, config);
          start = end + 1;
        }
      else
        {
          perror ("invalid format");
          free (config);
          return NULL;
        }
    }

  return config;
}

/* Parse a JSON file and return the result in a config struct.  */
struct compdetect_config *
parse_json_file (const char *file_path)
{
  FILE *file = fopen (file_path, "r");
  if (!file)
    {
      perror ("cannot open file");
      return NULL;
    }

  struct stat file_stat;
  if (stat (file_path, &file_stat) == -1)
    {
      perror ("cannot get file size");
      fclose (file);
      return NULL;
    }

  char *json_buf = malloc (file_stat.st_size + 1);
  if (!json_buf)
    {
      perror ("cannot allocate memory for json data");
      fclose (file);
      return NULL;
    }

  if (fread (json_buf, 1, file_stat.st_size, file) != file_stat.st_size)
    {
      perror ("cannot read file");
      fclose (file);
      free (json_buf);
      return NULL;
    }

  json_buf[file_stat.st_size] = '\0';
  struct compdetect_config *config = parse_json_string (json_buf);
  fclose (file);
  free (json_buf);

  return config;
}