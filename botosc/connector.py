from osc_sdk import OSCCall
from botosc import FiltersInternetService
from botosc import FiltersNet
from botosc import FiltersSecurityGroup
from botosc import FiltersListenerRule
from botosc import FiltersImage
from botosc import HealthCheck
from botosc import FiltersExportTask
from botosc import FiltersNetAccessPoint
from botosc import FiltersApiLog
from botosc import FiltersSubregion
from botosc import OsuExportToCreate
from botosc import LoadBalancerLight
from botosc import FiltersNetPeering
from botosc import Placement
from botosc import With
from botosc import FiltersVirtualGateway
from botosc import FiltersFlexibleGpu
from botosc import FiltersAccessKeys
from botosc import DirectLinkInterface
from botosc import FiltersKeypair
from botosc import FiltersVpnConnection
from botosc import FiltersClientGateway
from botosc import FiltersRouteTable
from botosc import FiltersDirectLink
from botosc import FiltersSnapshot
from botosc import FiltersNic
from botosc import FiltersPublicIp
from botosc import FiltersService
from botosc import FiltersVm
from botosc import FiltersDhcpOptions
from botosc import FiltersQuota
from botosc import FiltersTag
from botosc import AccessLog
from botosc import FiltersApiAccessRule
from botosc import PermissionsOnResourceCreation
from botosc import LinkNicToUpdate
from botosc import FiltersDirectLinkInterface
from botosc import FiltersSubnet
from botosc import FiltersProductType
from botosc import FiltersServerCertificate
from botosc import ListenerRuleForCreation
from botosc import FiltersVmsState
from botosc import FiltersVolume
from botosc import FiltersNatService
from botosc import FiltersVmType
from botosc import FiltersLoadBalancer
from botosc import FiltersCa
from typing import Optional
from dataclasses import asdict


class Connector(OSCCall):
    def accept_net_peering(self, net_peering_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("AcceptNetPeering", NetPeeringId=net_peering_id, **params)

    def check_authentication(self, login: str, password: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CheckAuthentication", Login=login, Password=password, **params)

    def create_access_key(self, dry_run: Optional[bool] = None, expiration_date: Optional[str] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if expiration_date is not None:
            params["ExpirationDate"] = expiration_date
        return self.make_request("CreateAccessKey", **params)

    def create_account(self, city: str, company_name: str, country: str, customer_id: str, email: str, first_name: str, last_name: str, zip_code: str, dry_run: Optional[bool] = None, job_title: Optional[str] = None, mobile_number: Optional[str] = None, phone_number: Optional[str] = None, state_province: Optional[str] = None, vat_number: Optional[str] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if job_title is not None:
            params["JobTitle"] = job_title
        if mobile_number is not None:
            params["MobileNumber"] = mobile_number
        if phone_number is not None:
            params["PhoneNumber"] = phone_number
        if state_province is not None:
            params["StateProvince"] = state_province
        if vat_number is not None:
            params["VatNumber"] = vat_number
        return self.make_request("CreateAccount", City=city, CompanyName=company_name, Country=country, CustomerId=customer_id, Email=email, FirstName=first_name, LastName=last_name, ZipCode=zip_code, **params)

    def create_api_access_rule(self, ca_ids: Optional[list[str]] = None, cns: Optional[list[str]] = None, description: Optional[str] = None, dry_run: Optional[bool] = None, ip_ranges: Optional[list[str]] = None):
        params = {}
        if ca_ids is not None:
            params["CaIds"] = ca_ids
        if cns is not None:
            params["Cns"] = cns
        if description is not None:
            params["Description"] = description
        if dry_run is not None:
            params["DryRun"] = dry_run
        if ip_ranges is not None:
            params["IpRanges"] = ip_ranges
        return self.make_request("CreateApiAccessRule", **params)

    def create_ca(self, ca_pem: str, description: Optional[str] = None, dry_run: Optional[bool] = None):
        params = {}
        if description is not None:
            params["Description"] = description
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateCa", CaPem=ca_pem, **params)

    def create_client_gateway(self, bgp_asn: int, connection_type: str, public_ip: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateClientGateway", BgpAsn=bgp_asn, ConnectionType=connection_type, PublicIp=public_ip, **params)

    def create_dhcp_options(self, domain_name: Optional[str] = None, domain_name_servers: Optional[list[str]] = None, dry_run: Optional[bool] = None, ntp_servers: Optional[list[str]] = None):
        params = {}
        if domain_name is not None:
            params["DomainName"] = domain_name
        if domain_name_servers is not None:
            params["DomainNameServers"] = domain_name_servers
        if dry_run is not None:
            params["DryRun"] = dry_run
        if ntp_servers is not None:
            params["NtpServers"] = ntp_servers
        return self.make_request("CreateDhcpOptions", **params)

    def create_direct_link(self, bandwidth: str, direct_link_name: str, location: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateDirectLink", Bandwidth=bandwidth, DirectLinkName=direct_link_name, Location=location, **params)

    def create_direct_link_interface(self, direct_link_id: str, direct_link_interface: "DirectLinkInterface", dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateDirectLinkInterface", DirectLinkId=direct_link_id, DirectLinkInterface=asdict(direct_link_interface), **params)

    def create_flexible_gpu(self, model_name: str, subregion_name: str, delete_on_vm_deletion: Optional[bool] = None, dry_run: Optional[bool] = None, generation: Optional[str] = None):
        params = {}
        if delete_on_vm_deletion is not None:
            params["DeleteOnVmDeletion"] = delete_on_vm_deletion
        if dry_run is not None:
            params["DryRun"] = dry_run
        if generation is not None:
            params["Generation"] = generation
        return self.make_request("CreateFlexibleGpu", ModelName=model_name, SubregionName=subregion_name, **params)

    def create_image(self, architecture: Optional[str] = None, block_device_mappings: Optional[list['BlockDeviceMappingImage']] = None, description: Optional[str] = None, dry_run: Optional[bool] = None, file_location: Optional[str] = None, image_name: Optional[str] = None, no_reboot: Optional[bool] = None, root_device_name: Optional[str] = None, source_image_id: Optional[str] = None, source_region_name: Optional[str] = None, vm_id: Optional[str] = None):
        params = {}
        if architecture is not None:
            params["Architecture"] = architecture
        if block_device_mappings is not None:
            params["BlockDeviceMappings"] = block_device_mappings
        if description is not None:
            params["Description"] = description
        if dry_run is not None:
            params["DryRun"] = dry_run
        if file_location is not None:
            params["FileLocation"] = file_location
        if image_name is not None:
            params["ImageName"] = image_name
        if no_reboot is not None:
            params["NoReboot"] = no_reboot
        if root_device_name is not None:
            params["RootDeviceName"] = root_device_name
        if source_image_id is not None:
            params["SourceImageId"] = source_image_id
        if source_region_name is not None:
            params["SourceRegionName"] = source_region_name
        if vm_id is not None:
            params["VmId"] = vm_id
        return self.make_request("CreateImage", **params)

    def create_image_export_task(self, image_id: str, osu_export: "OsuExportToCreate", dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateImageExportTask", ImageId=image_id, OsuExport=asdict(osu_export), **params)

    def create_internet_service(self, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateInternetService", **params)

    def create_keypair(self, keypair_name: str, dry_run: Optional[bool] = None, public_key: Optional[str] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if public_key is not None:
            params["PublicKey"] = public_key
        return self.make_request("CreateKeypair", KeypairName=keypair_name, **params)

    def create_listener_rule(self, listener: "LoadBalancerLight", listener_rule: "ListenerRuleForCreation", vm_ids: list[str], dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateListenerRule", Listener=asdict(listener), ListenerRule=asdict(listener_rule), VmIds=vm_ids, **params)

    def create_load_balancer(self, listeners: list['ListenerForCreation'], load_balancer_name: str, dry_run: Optional[bool] = None, load_balancer_type: Optional[str] = None, security_groups: Optional[list[str]] = None, subnets: Optional[list[str]] = None, subregion_names: Optional[list[str]] = None, tags: Optional[list['ResourceTag']] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if load_balancer_type is not None:
            params["LoadBalancerType"] = load_balancer_type
        if security_groups is not None:
            params["SecurityGroups"] = security_groups
        if subnets is not None:
            params["Subnets"] = subnets
        if subregion_names is not None:
            params["SubregionNames"] = subregion_names
        if tags is not None:
            params["Tags"] = tags
        return self.make_request("CreateLoadBalancer", Listeners=listeners, LoadBalancerName=load_balancer_name, **params)

    def create_load_balancer_listeners(self, listeners: list['ListenerForCreation'], load_balancer_name: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateLoadBalancerListeners", Listeners=listeners, LoadBalancerName=load_balancer_name, **params)

    def create_load_balancer_policy(self, load_balancer_name: str, policy_name: str, policy_type: str, cookie_name: Optional[str] = None, dry_run: Optional[bool] = None):
        params = {}
        if cookie_name is not None:
            params["CookieName"] = cookie_name
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateLoadBalancerPolicy", LoadBalancerName=load_balancer_name, PolicyName=policy_name, PolicyType=policy_type, **params)

    def create_load_balancer_tags(self, load_balancer_names: list[str], tags: list['ResourceTag'], dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateLoadBalancerTags", LoadBalancerNames=load_balancer_names, Tags=tags, **params)

    def create_nat_service(self, public_ip_id: str, subnet_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateNatService", PublicIpId=public_ip_id, SubnetId=subnet_id, **params)

    def create_net(self, ip_range: str, dry_run: Optional[bool] = None, tenancy: Optional[str] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if tenancy is not None:
            params["Tenancy"] = tenancy
        return self.make_request("CreateNet", IpRange=ip_range, **params)

    def create_net_access_point(self, net_id: str, service_name: str, dry_run: Optional[bool] = None, route_table_ids: Optional[list[str]] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if route_table_ids is not None:
            params["RouteTableIds"] = route_table_ids
        return self.make_request("CreateNetAccessPoint", NetId=net_id, ServiceName=service_name, **params)

    def create_net_peering(self, accepter_net_id: str, source_net_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateNetPeering", AccepterNetId=accepter_net_id, SourceNetId=source_net_id, **params)

    def create_nic(self, subnet_id: str, description: Optional[str] = None, dry_run: Optional[bool] = None, private_ips: Optional[list['PrivateIpLight']] = None, security_group_ids: Optional[list[str]] = None):
        params = {}
        if description is not None:
            params["Description"] = description
        if dry_run is not None:
            params["DryRun"] = dry_run
        if private_ips is not None:
            params["PrivateIps"] = private_ips
        if security_group_ids is not None:
            params["SecurityGroupIds"] = security_group_ids
        return self.make_request("CreateNic", SubnetId=subnet_id, **params)

    def create_public_ip(self, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreatePublicIp", **params)

    def create_route(self, destination_ip_range: str, route_table_id: str, dry_run: Optional[bool] = None, gateway_id: Optional[str] = None, nat_service_id: Optional[str] = None, net_peering_id: Optional[str] = None, nic_id: Optional[str] = None, vm_id: Optional[str] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if gateway_id is not None:
            params["GatewayId"] = gateway_id
        if nat_service_id is not None:
            params["NatServiceId"] = nat_service_id
        if net_peering_id is not None:
            params["NetPeeringId"] = net_peering_id
        if nic_id is not None:
            params["NicId"] = nic_id
        if vm_id is not None:
            params["VmId"] = vm_id
        return self.make_request("CreateRoute", DestinationIpRange=destination_ip_range, RouteTableId=route_table_id, **params)

    def create_route_table(self, net_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateRouteTable", NetId=net_id, **params)

    def create_security_group(self, description: str, security_group_name: str, dry_run: Optional[bool] = None, net_id: Optional[str] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if net_id is not None:
            params["NetId"] = net_id
        return self.make_request("CreateSecurityGroup", Description=description, SecurityGroupName=security_group_name, **params)

    def create_security_group_rule(self, flow: str, security_group_id: str, dry_run: Optional[bool] = None, from_port_range: Optional[int] = None, ip_protocol: Optional[str] = None, ip_range: Optional[str] = None, rules: Optional[list['SecurityGroupRule']] = None, security_group_account_id_to_link: Optional[str] = None, security_group_name_to_link: Optional[str] = None, to_port_range: Optional[int] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if from_port_range is not None:
            params["FromPortRange"] = from_port_range
        if ip_protocol is not None:
            params["IpProtocol"] = ip_protocol
        if ip_range is not None:
            params["IpRange"] = ip_range
        if rules is not None:
            params["Rules"] = rules
        if security_group_account_id_to_link is not None:
            params["SecurityGroupAccountIdToLink"] = security_group_account_id_to_link
        if security_group_name_to_link is not None:
            params["SecurityGroupNameToLink"] = security_group_name_to_link
        if to_port_range is not None:
            params["ToPortRange"] = to_port_range
        return self.make_request("CreateSecurityGroupRule", Flow=flow, SecurityGroupId=security_group_id, **params)

    def create_server_certificate(self, body: str, name: str, private_key: str, chain: Optional[str] = None, dry_run: Optional[bool] = None, path: Optional[str] = None):
        params = {}
        if chain is not None:
            params["Chain"] = chain
        if dry_run is not None:
            params["DryRun"] = dry_run
        if path is not None:
            params["Path"] = path
        return self.make_request("CreateServerCertificate", Body=body, Name=name, PrivateKey=private_key, **params)

    def create_snapshot(self, description: Optional[str] = None, dry_run: Optional[bool] = None, file_location: Optional[str] = None, snapshot_size: Optional[int] = None, source_region_name: Optional[str] = None, source_snapshot_id: Optional[str] = None, volume_id: Optional[str] = None):
        params = {}
        if description is not None:
            params["Description"] = description
        if dry_run is not None:
            params["DryRun"] = dry_run
        if file_location is not None:
            params["FileLocation"] = file_location
        if snapshot_size is not None:
            params["SnapshotSize"] = snapshot_size
        if source_region_name is not None:
            params["SourceRegionName"] = source_region_name
        if source_snapshot_id is not None:
            params["SourceSnapshotId"] = source_snapshot_id
        if volume_id is not None:
            params["VolumeId"] = volume_id
        return self.make_request("CreateSnapshot", **params)

    def create_snapshot_export_task(self, osu_export: "OsuExportToCreate", snapshot_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateSnapshotExportTask", OsuExport=asdict(osu_export), SnapshotId=snapshot_id, **params)

    def create_subnet(self, ip_range: str, net_id: str, dry_run: Optional[bool] = None, subregion_name: Optional[str] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if subregion_name is not None:
            params["SubregionName"] = subregion_name
        return self.make_request("CreateSubnet", IpRange=ip_range, NetId=net_id, **params)

    def create_tags(self, resource_ids: list[str], tags: list['ResourceTag'], dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateTags", ResourceIds=resource_ids, Tags=tags, **params)

    def create_virtual_gateway(self, connection_type: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateVirtualGateway", ConnectionType=connection_type, **params)

    def create_vms(self, image_id: str, block_device_mappings: Optional[list['BlockDeviceMappingVmCreation']] = None, boot_on_creation: Optional[bool] = None, bsu_optimized: Optional[bool] = None, client_token: Optional[str] = None, deletion_protection: Optional[bool] = None, dry_run: Optional[bool] = None, keypair_name: Optional[str] = None, max_vms_count: Optional[int] = None, min_vms_count: Optional[int] = None, nics: Optional[list['NicForVmCreation']] = None, performance: Optional[str] = None, placement: Optional["Placement"] = None, private_ips: Optional[list[str]] = None, security_group_ids: Optional[list[str]] = None, security_groups: Optional[list[str]] = None, subnet_id: Optional[str] = None, user_data: Optional[str] = None, vm_initiated_shutdown_behavior: Optional[str] = None, vm_type: Optional[str] = None):
        params = {}
        if block_device_mappings is not None:
            params["BlockDeviceMappings"] = block_device_mappings
        if boot_on_creation is not None:
            params["BootOnCreation"] = boot_on_creation
        if bsu_optimized is not None:
            params["BsuOptimized"] = bsu_optimized
        if client_token is not None:
            params["ClientToken"] = client_token
        if deletion_protection is not None:
            params["DeletionProtection"] = deletion_protection
        if dry_run is not None:
            params["DryRun"] = dry_run
        if keypair_name is not None:
            params["KeypairName"] = keypair_name
        if max_vms_count is not None:
            params["MaxVmsCount"] = max_vms_count
        if min_vms_count is not None:
            params["MinVmsCount"] = min_vms_count
        if nics is not None:
            params["Nics"] = nics
        if performance is not None:
            params["Performance"] = performance
        if placement is not None:
            params["Placement"] = asdict(placement)
        if private_ips is not None:
            params["PrivateIps"] = private_ips
        if security_group_ids is not None:
            params["SecurityGroupIds"] = security_group_ids
        if security_groups is not None:
            params["SecurityGroups"] = security_groups
        if subnet_id is not None:
            params["SubnetId"] = subnet_id
        if user_data is not None:
            params["UserData"] = user_data
        if vm_initiated_shutdown_behavior is not None:
            params["VmInitiatedShutdownBehavior"] = vm_initiated_shutdown_behavior
        if vm_type is not None:
            params["VmType"] = vm_type
        return self.make_request("CreateVms", ImageId=image_id, **params)

    def create_volume(self, subregion_name: str, dry_run: Optional[bool] = None, iops: Optional[int] = None, size: Optional[int] = None, snapshot_id: Optional[str] = None, volume_type: Optional[str] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if iops is not None:
            params["Iops"] = iops
        if size is not None:
            params["Size"] = size
        if snapshot_id is not None:
            params["SnapshotId"] = snapshot_id
        if volume_type is not None:
            params["VolumeType"] = volume_type
        return self.make_request("CreateVolume", SubregionName=subregion_name, **params)

    def create_vpn_connection(self, client_gateway_id: str, connection_type: str, virtual_gateway_id: str, dry_run: Optional[bool] = None, static_routes_only: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if static_routes_only is not None:
            params["StaticRoutesOnly"] = static_routes_only
        return self.make_request("CreateVpnConnection", ClientGatewayId=client_gateway_id, ConnectionType=connection_type, VirtualGatewayId=virtual_gateway_id, **params)

    def create_vpn_connection_route(self, destination_ip_range: str, vpn_connection_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("CreateVpnConnectionRoute", DestinationIpRange=destination_ip_range, VpnConnectionId=vpn_connection_id, **params)

    def delete_access_key(self, access_key_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteAccessKey", AccessKeyId=access_key_id, **params)

    def delete_api_access_rule(self, api_access_rule_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteApiAccessRule", ApiAccessRuleId=api_access_rule_id, **params)

    def delete_ca(self, ca_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteCa", CaId=ca_id, **params)

    def delete_client_gateway(self, client_gateway_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteClientGateway", ClientGatewayId=client_gateway_id, **params)

    def delete_dhcp_options(self, dhcp_options_set_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteDhcpOptions", DhcpOptionsSetId=dhcp_options_set_id, **params)

    def delete_direct_link(self, direct_link_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteDirectLink", DirectLinkId=direct_link_id, **params)

    def delete_direct_link_interface(self, direct_link_interface_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteDirectLinkInterface", DirectLinkInterfaceId=direct_link_interface_id, **params)

    def delete_export_task(self, export_task_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteExportTask", ExportTaskId=export_task_id, **params)

    def delete_flexible_gpu(self, flexible_gpu_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteFlexibleGpu", FlexibleGpuId=flexible_gpu_id, **params)

    def delete_image(self, image_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteImage", ImageId=image_id, **params)

    def delete_internet_service(self, internet_service_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteInternetService", InternetServiceId=internet_service_id, **params)

    def delete_keypair(self, keypair_name: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteKeypair", KeypairName=keypair_name, **params)

    def delete_listener_rule(self, listener_rule_name: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteListenerRule", ListenerRuleName=listener_rule_name, **params)

    def delete_load_balancer(self, load_balancer_name: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteLoadBalancer", LoadBalancerName=load_balancer_name, **params)

    def delete_load_balancer_listeners(self, load_balancer_name: str, load_balancer_ports: list[int], dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteLoadBalancerListeners", LoadBalancerName=load_balancer_name, LoadBalancerPorts=load_balancer_ports, **params)

    def delete_load_balancer_policy(self, load_balancer_name: str, policy_name: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteLoadBalancerPolicy", LoadBalancerName=load_balancer_name, PolicyName=policy_name, **params)

    def delete_load_balancer_tags(self, load_balancer_names: list[str], tags: list['ResourceLoadBalancerTag'], dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteLoadBalancerTags", LoadBalancerNames=load_balancer_names, Tags=tags, **params)

    def delete_nat_service(self, nat_service_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteNatService", NatServiceId=nat_service_id, **params)

    def delete_net(self, net_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteNet", NetId=net_id, **params)

    def delete_net_access_point(self, net_access_point_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteNetAccessPoint", NetAccessPointId=net_access_point_id, **params)

    def delete_net_peering(self, net_peering_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteNetPeering", NetPeeringId=net_peering_id, **params)

    def delete_nic(self, nic_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteNic", NicId=nic_id, **params)

    def delete_public_ip(self, dry_run: Optional[bool] = None, public_ip: Optional[str] = None, public_ip_id: Optional[str] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if public_ip is not None:
            params["PublicIp"] = public_ip
        if public_ip_id is not None:
            params["PublicIpId"] = public_ip_id
        return self.make_request("DeletePublicIp", **params)

    def delete_route(self, destination_ip_range: str, route_table_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteRoute", DestinationIpRange=destination_ip_range, RouteTableId=route_table_id, **params)

    def delete_route_table(self, route_table_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteRouteTable", RouteTableId=route_table_id, **params)

    def delete_security_group(self, dry_run: Optional[bool] = None, security_group_id: Optional[str] = None, security_group_name: Optional[str] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if security_group_id is not None:
            params["SecurityGroupId"] = security_group_id
        if security_group_name is not None:
            params["SecurityGroupName"] = security_group_name
        return self.make_request("DeleteSecurityGroup", **params)

    def delete_security_group_rule(self, flow: str, security_group_id: str, dry_run: Optional[bool] = None, from_port_range: Optional[int] = None, ip_protocol: Optional[str] = None, ip_range: Optional[str] = None, rules: Optional[list['SecurityGroupRule']] = None, security_group_account_id_to_unlink: Optional[str] = None, security_group_name_to_unlink: Optional[str] = None, to_port_range: Optional[int] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if from_port_range is not None:
            params["FromPortRange"] = from_port_range
        if ip_protocol is not None:
            params["IpProtocol"] = ip_protocol
        if ip_range is not None:
            params["IpRange"] = ip_range
        if rules is not None:
            params["Rules"] = rules
        if security_group_account_id_to_unlink is not None:
            params["SecurityGroupAccountIdToUnlink"] = security_group_account_id_to_unlink
        if security_group_name_to_unlink is not None:
            params["SecurityGroupNameToUnlink"] = security_group_name_to_unlink
        if to_port_range is not None:
            params["ToPortRange"] = to_port_range
        return self.make_request("DeleteSecurityGroupRule", Flow=flow, SecurityGroupId=security_group_id, **params)

    def delete_server_certificate(self, name: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteServerCertificate", Name=name, **params)

    def delete_snapshot(self, snapshot_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteSnapshot", SnapshotId=snapshot_id, **params)

    def delete_subnet(self, subnet_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteSubnet", SubnetId=subnet_id, **params)

    def delete_tags(self, resource_ids: list[str], tags: list['ResourceTag'], dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteTags", ResourceIds=resource_ids, Tags=tags, **params)

    def delete_virtual_gateway(self, virtual_gateway_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteVirtualGateway", VirtualGatewayId=virtual_gateway_id, **params)

    def delete_vms(self, vm_ids: list[str], dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteVms", VmIds=vm_ids, **params)

    def delete_volume(self, volume_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteVolume", VolumeId=volume_id, **params)

    def delete_vpn_connection(self, vpn_connection_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteVpnConnection", VpnConnectionId=vpn_connection_id, **params)

    def delete_vpn_connection_route(self, destination_ip_range: str, vpn_connection_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeleteVpnConnectionRoute", DestinationIpRange=destination_ip_range, VpnConnectionId=vpn_connection_id, **params)

    def deregister_vms_in_load_balancer(self, backend_vm_ids: list[str], load_balancer_name: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("DeregisterVmsInLoadBalancer", BackendVmIds=backend_vm_ids, LoadBalancerName=load_balancer_name, **params)

    def link_flexible_gpu(self, flexible_gpu_id: str, vm_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("LinkFlexibleGpu", FlexibleGpuId=flexible_gpu_id, VmId=vm_id, **params)

    def link_internet_service(self, internet_service_id: str, net_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("LinkInternetService", InternetServiceId=internet_service_id, NetId=net_id, **params)

    def link_nic(self, device_number: int, nic_id: str, vm_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("LinkNic", DeviceNumber=device_number, NicId=nic_id, VmId=vm_id, **params)

    def link_private_ips(self, nic_id: str, allow_relink: Optional[bool] = None, dry_run: Optional[bool] = None, private_ips: Optional[list[str]] = None, secondary_private_ip_count: Optional[int] = None):
        params = {}
        if allow_relink is not None:
            params["AllowRelink"] = allow_relink
        if dry_run is not None:
            params["DryRun"] = dry_run
        if private_ips is not None:
            params["PrivateIps"] = private_ips
        if secondary_private_ip_count is not None:
            params["SecondaryPrivateIpCount"] = secondary_private_ip_count
        return self.make_request("LinkPrivateIps", NicId=nic_id, **params)

    def link_public_ip(self, allow_relink: Optional[bool] = None, dry_run: Optional[bool] = None, nic_id: Optional[str] = None, private_ip: Optional[str] = None, public_ip: Optional[str] = None, public_ip_id: Optional[str] = None, vm_id: Optional[str] = None):
        params = {}
        if allow_relink is not None:
            params["AllowRelink"] = allow_relink
        if dry_run is not None:
            params["DryRun"] = dry_run
        if nic_id is not None:
            params["NicId"] = nic_id
        if private_ip is not None:
            params["PrivateIp"] = private_ip
        if public_ip is not None:
            params["PublicIp"] = public_ip
        if public_ip_id is not None:
            params["PublicIpId"] = public_ip_id
        if vm_id is not None:
            params["VmId"] = vm_id
        return self.make_request("LinkPublicIp", **params)

    def link_route_table(self, route_table_id: str, subnet_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("LinkRouteTable", RouteTableId=route_table_id, SubnetId=subnet_id, **params)

    def link_virtual_gateway(self, net_id: str, virtual_gateway_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("LinkVirtualGateway", NetId=net_id, VirtualGatewayId=virtual_gateway_id, **params)

    def link_volume(self, device_name: str, vm_id: str, volume_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("LinkVolume", DeviceName=device_name, VmId=vm_id, VolumeId=volume_id, **params)

    def read_access_keys(self, dry_run: Optional[bool] = None, filters: Optional["FiltersAccessKeys"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadAccessKeys", **params)

    def read_accounts(self, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("ReadAccounts", **params)

    def read_admin_password(self, vm_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("ReadAdminPassword", VmId=vm_id, **params)

    def read_api_access_rules(self, dry_run: Optional[bool] = None, filters: Optional["FiltersApiAccessRule"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadApiAccessRules", **params)

    def read_api_logs(self, dry_run: Optional[bool] = None, filters: Optional["FiltersApiLog"] = None, next_page_token: Optional[str] = None, results_per_page: Optional[int] = None, with_: Optional["With"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        if next_page_token is not None:
            params["NextPageToken"] = next_page_token
        if results_per_page is not None:
            params["ResultsPerPage"] = results_per_page
        if with_ is not None:
            params["With_"] = asdict(with_)
        return self.make_request("ReadApiLogs", **params)

    def read_cas(self, dry_run: Optional[bool] = None, filters: Optional["FiltersCa"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadCas", **params)

    def read_client_gateways(self, dry_run: Optional[bool] = None, filters: Optional["FiltersClientGateway"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadClientGateways", **params)

    def read_console_output(self, vm_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("ReadConsoleOutput", VmId=vm_id, **params)

    def read_consumption_account(self, from_date: str, to_date: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("ReadConsumptionAccount", FromDate=from_date, ToDate=to_date, **params)

    def read_dhcp_options(self, dry_run: Optional[bool] = None, filters: Optional["FiltersDhcpOptions"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadDhcpOptions", **params)

    def read_direct_link_interfaces(self, dry_run: Optional[bool] = None, filters: Optional["FiltersDirectLinkInterface"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadDirectLinkInterfaces", **params)

    def read_direct_links(self, dry_run: Optional[bool] = None, filters: Optional["FiltersDirectLink"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadDirectLinks", **params)

    def read_flexible_gpu_catalog(self, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("ReadFlexibleGpuCatalog", **params)

    def read_flexible_gpus(self, dry_run: Optional[bool] = None, filters: Optional["FiltersFlexibleGpu"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadFlexibleGpus", **params)

    def read_image_export_tasks(self, dry_run: Optional[bool] = None, filters: Optional["FiltersExportTask"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadImageExportTasks", **params)

    def read_images(self, dry_run: Optional[bool] = None, filters: Optional["FiltersImage"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadImages", **params)

    def read_internet_services(self, dry_run: Optional[bool] = None, filters: Optional["FiltersInternetService"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadInternetServices", **params)

    def read_keypairs(self, dry_run: Optional[bool] = None, filters: Optional["FiltersKeypair"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadKeypairs", **params)

    def read_listener_rules(self, dry_run: Optional[bool] = None, filters: Optional["FiltersListenerRule"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadListenerRules", **params)

    def read_load_balancer_tags(self, load_balancer_names: list[str], dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("ReadLoadBalancerTags", LoadBalancerNames=load_balancer_names, **params)

    def read_load_balancers(self, dry_run: Optional[bool] = None, filters: Optional["FiltersLoadBalancer"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadLoadBalancers", **params)

    def read_locations(self, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("ReadLocations", **params)

    def read_nat_services(self, dry_run: Optional[bool] = None, filters: Optional["FiltersNatService"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadNatServices", **params)

    def read_net_access_point_services(self, dry_run: Optional[bool] = None, filters: Optional["FiltersService"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadNetAccessPointServices", **params)

    def read_net_access_points(self, dry_run: Optional[bool] = None, filters: Optional["FiltersNetAccessPoint"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadNetAccessPoints", **params)

    def read_net_peerings(self, dry_run: Optional[bool] = None, filters: Optional["FiltersNetPeering"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadNetPeerings", **params)

    def read_nets(self, dry_run: Optional[bool] = None, filters: Optional["FiltersNet"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadNets", **params)

    def read_nics(self, dry_run: Optional[bool] = None, filters: Optional["FiltersNic"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadNics", **params)

    def read_product_types(self, dry_run: Optional[bool] = None, filters: Optional["FiltersProductType"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadProductTypes", **params)

    def read_public_ip_ranges(self, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("ReadPublicIpRanges", **params)

    def read_public_ips(self, dry_run: Optional[bool] = None, filters: Optional["FiltersPublicIp"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadPublicIps", **params)

    def read_quotas(self, dry_run: Optional[bool] = None, filters: Optional["FiltersQuota"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadQuotas", **params)

    def read_regions(self, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("ReadRegions", **params)

    def read_route_tables(self, dry_run: Optional[bool] = None, filters: Optional["FiltersRouteTable"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadRouteTables", **params)

    def read_secret_access_key(self, access_key_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("ReadSecretAccessKey", AccessKeyId=access_key_id, **params)

    def read_security_groups(self, dry_run: Optional[bool] = None, filters: Optional["FiltersSecurityGroup"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadSecurityGroups", **params)

    def read_server_certificates(self, dry_run: Optional[bool] = None, filters: Optional["FiltersServerCertificate"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadServerCertificates", **params)

    def read_snapshot_export_tasks(self, dry_run: Optional[bool] = None, filters: Optional["FiltersExportTask"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadSnapshotExportTasks", **params)

    def read_snapshots(self, dry_run: Optional[bool] = None, filters: Optional["FiltersSnapshot"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadSnapshots", **params)

    def read_subnets(self, dry_run: Optional[bool] = None, filters: Optional["FiltersSubnet"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadSubnets", **params)

    def read_subregions(self, dry_run: Optional[bool] = None, filters: Optional["FiltersSubregion"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadSubregions", **params)

    def read_tags(self, dry_run: Optional[bool] = None, filters: Optional["FiltersTag"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadTags", **params)

    def read_virtual_gateways(self, dry_run: Optional[bool] = None, filters: Optional["FiltersVirtualGateway"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadVirtualGateways", **params)

    def read_vm_types(self, dry_run: Optional[bool] = None, filters: Optional["FiltersVmType"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadVmTypes", **params)

    def read_vms(self, dry_run: Optional[bool] = None, filters: Optional["FiltersVm"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadVms", **params)

    def read_vms_health(self, load_balancer_name: str, backend_vm_ids: Optional[list[str]] = None, dry_run: Optional[bool] = None):
        params = {}
        if backend_vm_ids is not None:
            params["BackendVmIds"] = backend_vm_ids
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("ReadVmsHealth", LoadBalancerName=load_balancer_name, **params)

    def read_vms_state(self, all_vms: Optional[bool] = None, dry_run: Optional[bool] = None, filters: Optional["FiltersVmsState"] = None):
        params = {}
        if all_vms is not None:
            params["AllVms"] = all_vms
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadVmsState", **params)

    def read_volumes(self, dry_run: Optional[bool] = None, filters: Optional["FiltersVolume"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadVolumes", **params)

    def read_vpn_connections(self, dry_run: Optional[bool] = None, filters: Optional["FiltersVpnConnection"] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = asdict(filters)
        return self.make_request("ReadVpnConnections", **params)

    def reboot_vms(self, vm_ids: list[str], dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("RebootVms", VmIds=vm_ids, **params)

    def register_vms_in_load_balancer(self, backend_vm_ids: list[str], load_balancer_name: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("RegisterVmsInLoadBalancer", BackendVmIds=backend_vm_ids, LoadBalancerName=load_balancer_name, **params)

    def reject_net_peering(self, net_peering_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("RejectNetPeering", NetPeeringId=net_peering_id, **params)

    def reset_account_password(self, password: str, token: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("ResetAccountPassword", Password=password, Token=token, **params)

    def send_reset_password_email(self, email: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("SendResetPasswordEmail", Email=email, **params)

    def start_vms(self, vm_ids: list[str], dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("StartVms", VmIds=vm_ids, **params)

    def stop_vms(self, vm_ids: list[str], dry_run: Optional[bool] = None, force_stop: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if force_stop is not None:
            params["ForceStop"] = force_stop
        return self.make_request("StopVms", VmIds=vm_ids, **params)

    def unlink_flexible_gpu(self, flexible_gpu_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("UnlinkFlexibleGpu", FlexibleGpuId=flexible_gpu_id, **params)

    def unlink_internet_service(self, internet_service_id: str, net_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("UnlinkInternetService", InternetServiceId=internet_service_id, NetId=net_id, **params)

    def unlink_nic(self, link_nic_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("UnlinkNic", LinkNicId=link_nic_id, **params)

    def unlink_private_ips(self, nic_id: str, private_ips: list[str], dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("UnlinkPrivateIps", NicId=nic_id, PrivateIps=private_ips, **params)

    def unlink_public_ip(self, dry_run: Optional[bool] = None, link_public_ip_id: Optional[str] = None, public_ip: Optional[str] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if link_public_ip_id is not None:
            params["LinkPublicIpId"] = link_public_ip_id
        if public_ip is not None:
            params["PublicIp"] = public_ip
        return self.make_request("UnlinkPublicIp", **params)

    def unlink_route_table(self, link_route_table_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("UnlinkRouteTable", LinkRouteTableId=link_route_table_id, **params)

    def unlink_virtual_gateway(self, net_id: str, virtual_gateway_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("UnlinkVirtualGateway", NetId=net_id, VirtualGatewayId=virtual_gateway_id, **params)

    def unlink_volume(self, volume_id: str, dry_run: Optional[bool] = None, force_unlink: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if force_unlink is not None:
            params["ForceUnlink"] = force_unlink
        return self.make_request("UnlinkVolume", VolumeId=volume_id, **params)

    def update_access_key(self, access_key_id: str, state: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("UpdateAccessKey", AccessKeyId=access_key_id, State=state, **params)

    def update_account(self, city: Optional[str] = None, company_name: Optional[str] = None, country: Optional[str] = None, dry_run: Optional[bool] = None, email: Optional[str] = None, first_name: Optional[str] = None, job_title: Optional[str] = None, last_name: Optional[str] = None, mobile_number: Optional[str] = None, phone_number: Optional[str] = None, state_province: Optional[str] = None, vat_number: Optional[str] = None, zip_code: Optional[str] = None):
        params = {}
        if city is not None:
            params["City"] = city
        if company_name is not None:
            params["CompanyName"] = company_name
        if country is not None:
            params["Country"] = country
        if dry_run is not None:
            params["DryRun"] = dry_run
        if email is not None:
            params["Email"] = email
        if first_name is not None:
            params["FirstName"] = first_name
        if job_title is not None:
            params["JobTitle"] = job_title
        if last_name is not None:
            params["LastName"] = last_name
        if mobile_number is not None:
            params["MobileNumber"] = mobile_number
        if phone_number is not None:
            params["PhoneNumber"] = phone_number
        if state_province is not None:
            params["StateProvince"] = state_province
        if vat_number is not None:
            params["VatNumber"] = vat_number
        if zip_code is not None:
            params["ZipCode"] = zip_code
        return self.make_request("UpdateAccount", **params)

    def update_api_access_rule(self, api_access_rule_id: str, ca_ids: Optional[list[str]] = None, cns: Optional[list[str]] = None, description: Optional[str] = None, dry_run: Optional[bool] = None, ip_ranges: Optional[list[str]] = None):
        params = {}
        if ca_ids is not None:
            params["CaIds"] = ca_ids
        if cns is not None:
            params["Cns"] = cns
        if description is not None:
            params["Description"] = description
        if dry_run is not None:
            params["DryRun"] = dry_run
        if ip_ranges is not None:
            params["IpRanges"] = ip_ranges
        return self.make_request("UpdateApiAccessRule", ApiAccessRuleId=api_access_rule_id, **params)

    def update_ca(self, ca_id: str, description: Optional[str] = None, dry_run: Optional[bool] = None):
        params = {}
        if description is not None:
            params["Description"] = description
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("UpdateCa", CaId=ca_id, **params)

    def update_flexible_gpu(self, flexible_gpu_id: str, delete_on_vm_deletion: Optional[bool] = None, dry_run: Optional[bool] = None):
        params = {}
        if delete_on_vm_deletion is not None:
            params["DeleteOnVmDeletion"] = delete_on_vm_deletion
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("UpdateFlexibleGpu", FlexibleGpuId=flexible_gpu_id, **params)

    def update_image(self, image_id: str, permissions_to_launch: "PermissionsOnResourceCreation", dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("UpdateImage", ImageId=image_id, PermissionsToLaunch=asdict(permissions_to_launch), **params)

    def update_listener_rule(self, listener_rule_name: str, dry_run: Optional[bool] = None, host_pattern: Optional[str] = None, path_pattern: Optional[str] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if host_pattern is not None:
            params["HostPattern"] = host_pattern
        if path_pattern is not None:
            params["PathPattern"] = path_pattern
        return self.make_request("UpdateListenerRule", ListenerRuleName=listener_rule_name, **params)

    def update_load_balancer(self, load_balancer_name: str, access_log: Optional["AccessLog"] = None, dry_run: Optional[bool] = None, health_check: Optional["HealthCheck"] = None, load_balancer_port: Optional[int] = None, policy_names: Optional[list[str]] = None, security_groups: Optional[list[str]] = None, server_certificate_id: Optional[str] = None):
        params = {}
        if access_log is not None:
            params["AccessLog"] = asdict(access_log)
        if dry_run is not None:
            params["DryRun"] = dry_run
        if health_check is not None:
            params["HealthCheck"] = asdict(health_check)
        if load_balancer_port is not None:
            params["LoadBalancerPort"] = load_balancer_port
        if policy_names is not None:
            params["PolicyNames"] = policy_names
        if security_groups is not None:
            params["SecurityGroups"] = security_groups
        if server_certificate_id is not None:
            params["ServerCertificateId"] = server_certificate_id
        return self.make_request("UpdateLoadBalancer", LoadBalancerName=load_balancer_name, **params)

    def update_net(self, dhcp_options_set_id: str, net_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("UpdateNet", DhcpOptionsSetId=dhcp_options_set_id, NetId=net_id, **params)

    def update_net_access_point(self, net_access_point_id: str, add_route_table_ids: Optional[list[str]] = None, dry_run: Optional[bool] = None, remove_route_table_ids: Optional[list[str]] = None):
        params = {}
        if add_route_table_ids is not None:
            params["AddRouteTableIds"] = add_route_table_ids
        if dry_run is not None:
            params["DryRun"] = dry_run
        if remove_route_table_ids is not None:
            params["RemoveRouteTableIds"] = remove_route_table_ids
        return self.make_request("UpdateNetAccessPoint", NetAccessPointId=net_access_point_id, **params)

    def update_nic(self, nic_id: str, description: Optional[str] = None, dry_run: Optional[bool] = None, link_nic: Optional["LinkNicToUpdate"] = None, security_group_ids: Optional[list[str]] = None):
        params = {}
        if description is not None:
            params["Description"] = description
        if dry_run is not None:
            params["DryRun"] = dry_run
        if link_nic is not None:
            params["LinkNic"] = asdict(link_nic)
        if security_group_ids is not None:
            params["SecurityGroupIds"] = security_group_ids
        return self.make_request("UpdateNic", NicId=nic_id, **params)

    def update_route(self, destination_ip_range: str, route_table_id: str, dry_run: Optional[bool] = None, gateway_id: Optional[str] = None, nat_service_id: Optional[str] = None, net_peering_id: Optional[str] = None, nic_id: Optional[str] = None, vm_id: Optional[str] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if gateway_id is not None:
            params["GatewayId"] = gateway_id
        if nat_service_id is not None:
            params["NatServiceId"] = nat_service_id
        if net_peering_id is not None:
            params["NetPeeringId"] = net_peering_id
        if nic_id is not None:
            params["NicId"] = nic_id
        if vm_id is not None:
            params["VmId"] = vm_id
        return self.make_request("UpdateRoute", DestinationIpRange=destination_ip_range, RouteTableId=route_table_id, **params)

    def update_route_propagation(self, enable: bool, route_table_id: str, virtual_gateway_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("UpdateRoutePropagation", Enable=enable, RouteTableId=route_table_id, VirtualGatewayId=virtual_gateway_id, **params)

    def update_server_certificate(self, name: str, dry_run: Optional[bool] = None, new_name: Optional[str] = None, new_path: Optional[str] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if new_name is not None:
            params["NewName"] = new_name
        if new_path is not None:
            params["NewPath"] = new_path
        return self.make_request("UpdateServerCertificate", Name=name, **params)

    def update_snapshot(self, permissions_to_create_volume: "PermissionsOnResourceCreation", snapshot_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("UpdateSnapshot", PermissionsToCreateVolume=asdict(permissions_to_create_volume), SnapshotId=snapshot_id, **params)

    def update_subnet(self, map_public_ip_on_launch: bool, subnet_id: str, dry_run: Optional[bool] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        return self.make_request("UpdateSubnet", MapPublicIpOnLaunch=map_public_ip_on_launch, SubnetId=subnet_id, **params)

    def update_vm(self, vm_id: str, block_device_mappings: Optional[list['BlockDeviceMappingVmUpdate']] = None, bsu_optimized: Optional[bool] = None, deletion_protection: Optional[bool] = None, dry_run: Optional[bool] = None, is_source_dest_checked: Optional[bool] = None, keypair_name: Optional[str] = None, performance: Optional[str] = None, security_group_ids: Optional[list[str]] = None, user_data: Optional[str] = None, vm_initiated_shutdown_behavior: Optional[str] = None, vm_type: Optional[str] = None):
        params = {}
        if block_device_mappings is not None:
            params["BlockDeviceMappings"] = block_device_mappings
        if bsu_optimized is not None:
            params["BsuOptimized"] = bsu_optimized
        if deletion_protection is not None:
            params["DeletionProtection"] = deletion_protection
        if dry_run is not None:
            params["DryRun"] = dry_run
        if is_source_dest_checked is not None:
            params["IsSourceDestChecked"] = is_source_dest_checked
        if keypair_name is not None:
            params["KeypairName"] = keypair_name
        if performance is not None:
            params["Performance"] = performance
        if security_group_ids is not None:
            params["SecurityGroupIds"] = security_group_ids
        if user_data is not None:
            params["UserData"] = user_data
        if vm_initiated_shutdown_behavior is not None:
            params["VmInitiatedShutdownBehavior"] = vm_initiated_shutdown_behavior
        if vm_type is not None:
            params["VmType"] = vm_type
        return self.make_request("UpdateVm", VmId=vm_id, **params)

    def update_volume(self, volume_id: str, dry_run: Optional[bool] = None, iops: Optional[int] = None, size: Optional[int] = None, volume_type: Optional[str] = None):
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if iops is not None:
            params["Iops"] = iops
        if size is not None:
            params["Size"] = size
        if volume_type is not None:
            params["VolumeType"] = volume_type
        return self.make_request("UpdateVolume", VolumeId=volume_id, **params)

