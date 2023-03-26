all: server client standalone

server: compdetect_server.c compdetect_config_parser.c
		gcc -o compdetect_server compdetect_server.c compdetect_config_parser.c

client: compdetect_client.c compdetect_config_parser.c
		gcc -o compdetect_client compdetect_client.c compdetect_config_parser.c

standalone: compdetect.c compdetect_config_parser.c
		gcc -o compdetect compdetect.c compdetect_config_parser.c

clean:
		rm compdetect_server compdetect_client compdetect