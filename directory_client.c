/* 
Serval DNA directory service client
Copyright (C) 2013 Serval Project Inc.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


/*
 
 Serval Directory Service client
 
 When servald starts, load the SID, IP (or domain name) & port of a directory server.
 When an interface comes up with a route to this server, and periodically thereafter, 
 send our SID name and number to the configured server.
 
 When we perform a lookup, send an additional copy of the request to the directory server.
 
 */

#include "serval_types.h"
#include "cli.h"
#include "str.h"
#include "overlay_address.h"
#include "overlay_packet.h"
#include "overlay_buffer.h"
#include "conf.h"
#include "overlay_interface.h"
#include "keyring.h"
#include "serval.h" // for overlay_send_frame()
#include "route_link.h"

__thread struct subscriber *directory_service;

static void directory_update(struct sched_ent *alarm);

static struct profile_total directory_timing={
  .name="directory_update",
};

struct sched_ent directory_alarm={
  .function=directory_update,
  .stats=&directory_timing,
};
#define DIRECTORY_UPDATE_INTERVAL 120000

// send a registration packet
static void directory_send(struct subscriber *directory_service, struct subscriber *source, const char *did, const char *name)
{
  // Used by tests
  INFOF("Sending directory registration for %s*, %s, %s to %s*", 
	alloca_tohex_sid_t_trunc(source->sid, 14), did, name, alloca_tohex_sid_t_trunc(directory_service->sid, 14));
	
  struct internal_mdp_header header;
  bzero(&header, sizeof header);
  
  header.source = source;
  header.source_port = MDP_PORT_NOREPLY;
  header.destination = directory_service;
  header.destination_port = MDP_PORT_DIRECTORY;
  header.qos = OQ_ORDINARY;
  char buff[256];
  struct overlay_buffer *payload = ob_static((unsigned char*)buff, sizeof buff);
  ob_limitsize(payload, snprintf(buff, sizeof buff, "%s|%s", did, name));
  overlay_send_frame(&header, payload);
  ob_free(payload);
}

// send a registration packet for each unlocked identity
static void directory_send_keyring(struct subscriber *directory_service){
  keyring_iterator it;
  keyring_iterator_start(keyring, &it);
  while(keyring_next_keytype(&it, KEYTYPE_DID)){
    if (it.identity->subscriber && it.identity->subscriber->reachable == REACHABLE_SELF){
      const char *unpackedDid = (const char *) it.keypair->private_key;
      const char *name = (const char *) it.keypair->public_key;
      directory_send(directory_service, it.identity->subscriber, unpackedDid, name);
    }
  }
}

static void directory_update(struct sched_ent *alarm){
  if (directory_service){
    if (directory_service->reachable & REACHABLE){
      directory_send_keyring(directory_service);
      
      unschedule(alarm);
      alarm->alarm = gettime_ms() + DIRECTORY_UPDATE_INTERVAL;
      alarm->deadline = alarm->alarm + 10000;
      schedule(alarm);
    }else{
      // always attempt to reload the address, may depend on DNS resolution
      struct network_destination *destination = load_subscriber_address(directory_service);
      if (destination){
	overlay_send_probe(directory_service, destination, OQ_MESH_MANAGEMENT);
	release_destination_ref(destination);
      }
    }
  }
}

int directory_service_init(){
  if (is_sid_t_any(config.directory.service)) {
    directory_service = NULL;
  }else{
    directory_service = find_subscriber(config.directory.service.binary, SID_SIZE, 1);
    if (!directory_service){
      WHYF("Failed to create subscriber record");
    }else{
      // used by tests
      INFOF("ADD DIRECTORY SERVICE %s", alloca_tohex_sid_t(directory_service->sid));
    }
  }
  unschedule(&directory_alarm);
  directory_update(&directory_alarm);
  return 0;
}

// called when we discover a route to the directory service SID
int directory_registration(){
  // give the route & SAS keys a moment to propagate
  unschedule(&directory_alarm);
  directory_alarm.alarm = gettime_ms() + 200;
  directory_alarm.deadline = directory_alarm.alarm + 10000;
  schedule(&directory_alarm);
  return 0;
}

static void interface_change(struct overlay_interface *UNUSED(interface)){
  directory_registration();
}

DEFINE_TRIGGER(iupdown, interface_change);

static void directory_link_changed(struct subscriber *subscriber, int UNUSED(prior_reachable)){
  if (subscriber==directory_service)
    directory_registration();
}

DEFINE_TRIGGER(link_change, directory_link_changed);
