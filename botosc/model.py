from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from apischema.aliases import alias

from botosc.mixin import VmMixin

from .base import BaseObject
from .utils import to_camelcase


@alias(to_camelcase)
@dataclass
class AccepterNet(BaseObject):
    account_id: Optional[str] = None
    ip_range: Optional[str] = None
    net_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class AccessKey(BaseObject):
    access_key_id: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    last_modification_date: Optional[str] = None
    state: Optional[str] = None


@alias(to_camelcase)
@dataclass
class AccessKeySecretKey(BaseObject):
    access_key_id: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    last_modification_date: Optional[str] = None
    secret_key: Optional[str] = None
    state: Optional[str] = None


@alias(to_camelcase)
@dataclass
class AccessLog(BaseObject):
    is_enabled: Optional[bool] = None
    osu_bucket_name: Optional[str] = None
    osu_bucket_prefix: Optional[str] = None
    publication_interval: Optional[int] = None


@alias(to_camelcase)
@dataclass
class Account(BaseObject):
    account_id: Optional[str] = None
    additional_emails: Optional[list[str]] = None
    city: Optional[str] = None
    company_name: Optional[str] = None
    country: Optional[str] = None
    customer_id: Optional[str] = None
    email: Optional[str] = None
    first_name: Optional[str] = None
    job_title: Optional[str] = None
    last_name: Optional[str] = None
    mobile_number: Optional[str] = None
    phone_number: Optional[str] = None
    state_province: Optional[str] = None
    vat_number: Optional[str] = None
    zip_code: Optional[str] = None


@alias(to_camelcase)
@dataclass
class ApiAccessPolicy(BaseObject):
    max_access_key_expiration_seconds: Optional[int] = None
    require_trusted_env: Optional[bool] = None


@alias(to_camelcase)
@dataclass
class ApiAccessRule(BaseObject):
    api_access_rule_id: Optional[str] = None
    ca_ids: Optional[list[str]] = None
    cns: Optional[list[str]] = None
    description: Optional[str] = None
    ip_ranges: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class ApplicationStickyCookiePolicy(BaseObject):
    cookie_name: Optional[str] = None
    policy_name: Optional[str] = None


@alias(to_camelcase)
@dataclass
class BackendVmHealth(BaseObject):
    description: Optional[str] = None
    state: Optional[str] = None
    state_reason: Optional[str] = None
    vm_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class BlockDeviceMappingCreated(BaseObject):
    bsu: Optional[BsuCreated] = None
    device_name: Optional[str] = None


@alias(to_camelcase)
@dataclass
class BlockDeviceMappingImage(BaseObject):
    bsu: Optional[BsuToCreate] = None
    device_name: Optional[str] = None
    virtual_device_name: Optional[str] = None


@alias(to_camelcase)
@dataclass
class BlockDeviceMappingVmCreation(BaseObject):
    bsu: Optional[BsuToCreate] = None
    device_name: Optional[str] = None
    no_device: Optional[str] = None
    virtual_device_name: Optional[str] = None


@alias(to_camelcase)
@dataclass
class BlockDeviceMappingVmUpdate(BaseObject):
    bsu: Optional[BsuToUpdateVm] = None
    device_name: Optional[str] = None
    no_device: Optional[str] = None
    virtual_device_name: Optional[str] = None


@alias(to_camelcase)
@dataclass
class BsuCreated(BaseObject):
    delete_on_vm_deletion: Optional[bool] = None
    link_date: Optional[str] = None
    state: Optional[str] = None
    volume_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class BsuToCreate(BaseObject):
    delete_on_vm_deletion: Optional[bool] = None
    iops: Optional[int] = None
    snapshot_id: Optional[str] = None
    volume_size: Optional[int] = None
    volume_type: Optional[str] = None


@alias(to_camelcase)
@dataclass
class BsuToUpdateVm(BaseObject):
    delete_on_vm_deletion: Optional[bool] = None
    volume_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Ca(BaseObject):
    ca_fingerprint: Optional[str] = None
    ca_id: Optional[str] = None
    description: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Catalog(BaseObject):
    entries: Optional[list[CatalogEntry]] = None


@alias(to_camelcase)
@dataclass
class CatalogEntry(BaseObject):
    category: Optional[str] = None
    flags: Optional[str] = None
    operation: Optional[str] = None
    service: Optional[str] = None
    subregion_name: Optional[str] = None
    title: Optional[str] = None
    type: Optional[str] = None
    unit_price: Optional[float] = None


@alias(to_camelcase)
@dataclass
class ClientGateway(BaseObject):
    bgp_asn: Optional[int] = None
    client_gateway_id: Optional[str] = None
    connection_type: Optional[str] = None
    public_ip: Optional[str] = None
    state: Optional[str] = None
    tags: Optional[list[ResourceTag]] = None


@alias(to_camelcase)
@dataclass
class ConsumptionEntry(BaseObject):
    account_id: Optional[str] = None
    category: Optional[str] = None
    from_date: Optional[str] = None
    operation: Optional[str] = None
    paying_account_id: Optional[str] = None
    service: Optional[str] = None
    subregion_name: Optional[str] = None
    title: Optional[str] = None
    to_date: Optional[str] = None
    type: Optional[str] = None
    value: Optional[int] = None


@alias(to_camelcase)
@dataclass
class DhcpOptionsSet(BaseObject):
    default: Optional[bool] = None
    dhcp_options_set_id: Optional[str] = None
    domain_name: Optional[str] = None
    domain_name_servers: Optional[list[str]] = None
    ntp_servers: Optional[list[str]] = None
    tags: Optional[list[ResourceTag]] = None


@alias(to_camelcase)
@dataclass
class DirectLink(BaseObject):
    account_id: Optional[str] = None
    bandwidth: Optional[str] = None
    direct_link_id: Optional[str] = None
    direct_link_name: Optional[str] = None
    location: Optional[str] = None
    region_name: Optional[str] = None
    state: Optional[str] = None


@alias(to_camelcase)
@dataclass
class DirectLinkInterface(BaseObject):
    bgp_asn: int
    direct_link_interface_name: str
    virtual_gateway_id: str
    vlan: int
    bgp_key: Optional[str] = None
    client_private_ip: Optional[str] = None
    outscale_private_ip: Optional[str] = None


@alias(to_camelcase)
@dataclass
class DirectLinkInterfaces(BaseObject):
    account_id: Optional[str] = None
    bgp_asn: Optional[int] = None
    bgp_key: Optional[str] = None
    client_private_ip: Optional[str] = None
    direct_link_id: Optional[str] = None
    direct_link_interface_id: Optional[str] = None
    direct_link_interface_name: Optional[str] = None
    interface_type: Optional[str] = None
    location: Optional[str] = None
    outscale_private_ip: Optional[str] = None
    state: Optional[str] = None
    virtual_gateway_id: Optional[str] = None
    vlan: Optional[int] = None


@alias(to_camelcase)
@dataclass
class Errors(BaseObject):
    code: Optional[str] = None
    details: Optional[str] = None
    type: Optional[str] = None


@alias(to_camelcase)
@dataclass
class FiltersAccessKeys(BaseObject):
    access_key_ids: Optional[list[str]] = None
    states: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersApiAccessRule(BaseObject):
    api_access_rule_ids: Optional[list[str]] = None
    ca_ids: Optional[list[str]] = None
    cns: Optional[list[str]] = None
    descriptions: Optional[list[str]] = None
    ip_ranges: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersApiLog(BaseObject):
    query_access_keys: Optional[list[str]] = None
    query_api_names: Optional[list[str]] = None
    query_call_names: Optional[list[str]] = None
    query_date_after: Optional[str] = None
    query_date_before: Optional[str] = None
    query_ip_addresses: Optional[list[str]] = None
    query_user_agents: Optional[list[str]] = None
    request_ids: Optional[list[str]] = None
    response_status_codes: Optional[list[int]] = None


@alias(to_camelcase)
@dataclass
class FiltersCa(BaseObject):
    ca_fingerprints: Optional[list[str]] = None
    ca_ids: Optional[list[str]] = None
    descriptions: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersClientGateway(BaseObject):
    bgp_asns: Optional[list[int]] = None
    client_gateway_ids: Optional[list[str]] = None
    connection_types: Optional[list[str]] = None
    public_ips: Optional[list[str]] = None
    states: Optional[list[str]] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersDhcpOptions(BaseObject):
    default: Optional[bool] = None
    dhcp_options_set_ids: Optional[list[str]] = None
    domain_name_servers: Optional[list[str]] = None
    domain_names: Optional[list[str]] = None
    ntp_servers: Optional[list[str]] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersDirectLink(BaseObject):
    direct_link_ids: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersDirectLinkInterface(BaseObject):
    direct_link_ids: Optional[list[str]] = None
    direct_link_interface_ids: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersExportTask(BaseObject):
    task_ids: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersFlexibleGpu(BaseObject):
    delete_on_vm_deletion: Optional[bool] = None
    flexible_gpu_ids: Optional[list[str]] = None
    generations: Optional[list[str]] = None
    model_names: Optional[list[str]] = None
    states: Optional[list[str]] = None
    subregion_names: Optional[list[str]] = None
    vm_ids: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersImage(BaseObject):
    account_aliases: Optional[list[str]] = None
    account_ids: Optional[list[str]] = None
    architectures: Optional[list[str]] = None
    block_device_mapping_delete_on_vm_deletion: Optional[bool] = None
    block_device_mapping_device_names: Optional[list[str]] = None
    block_device_mapping_snapshot_ids: Optional[list[str]] = None
    block_device_mapping_volume_sizes: Optional[list[int]] = None
    block_device_mapping_volume_types: Optional[list[str]] = None
    descriptions: Optional[list[str]] = None
    file_locations: Optional[list[str]] = None
    hypervisors: Optional[list[str]] = None
    image_ids: Optional[list[str]] = None
    image_names: Optional[list[str]] = None
    permissions_to_launch_account_ids: Optional[list[str]] = None
    permissions_to_launch_global_permission: Optional[bool] = None
    product_codes: Optional[list[str]] = None
    root_device_names: Optional[list[str]] = None
    root_device_types: Optional[list[str]] = None
    states: Optional[list[str]] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    virtualization_types: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersInternetService(BaseObject):
    internet_service_ids: Optional[list[str]] = None
    link_net_ids: Optional[list[str]] = None
    link_states: Optional[list[str]] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersKeypair(BaseObject):
    keypair_fingerprints: Optional[list[str]] = None
    keypair_names: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersListenerRule(BaseObject):
    listener_rule_names: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersLoadBalancer(BaseObject):
    load_balancer_names: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersNatService(BaseObject):
    nat_service_ids: Optional[list[str]] = None
    net_ids: Optional[list[str]] = None
    states: Optional[list[str]] = None
    subnet_ids: Optional[list[str]] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersNet(BaseObject):
    dhcp_options_set_ids: Optional[list[str]] = None
    ip_ranges: Optional[list[str]] = None
    is_default: Optional[bool] = None
    net_ids: Optional[list[str]] = None
    states: Optional[list[str]] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersNetAccessPoint(BaseObject):
    net_access_point_ids: Optional[list[str]] = None
    net_ids: Optional[list[str]] = None
    service_names: Optional[list[str]] = None
    states: Optional[list[str]] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersNetPeering(BaseObject):
    accepter_net_account_ids: Optional[list[str]] = None
    accepter_net_ip_ranges: Optional[list[str]] = None
    accepter_net_net_ids: Optional[list[str]] = None
    net_peering_ids: Optional[list[str]] = None
    source_net_account_ids: Optional[list[str]] = None
    source_net_ip_ranges: Optional[list[str]] = None
    source_net_net_ids: Optional[list[str]] = None
    state_messages: Optional[list[str]] = None
    state_names: Optional[list[str]] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersNic(BaseObject):
    descriptions: Optional[list[str]] = None
    is_source_dest_check: Optional[bool] = None
    link_nic_delete_on_vm_deletion: Optional[bool] = None
    link_nic_device_numbers: Optional[list[int]] = None
    link_nic_link_nic_ids: Optional[list[str]] = None
    link_nic_states: Optional[list[str]] = None
    link_nic_vm_account_ids: Optional[list[str]] = None
    link_nic_vm_ids: Optional[list[str]] = None
    link_public_ip_account_ids: Optional[list[str]] = None
    link_public_ip_link_public_ip_ids: Optional[list[str]] = None
    link_public_ip_public_ip_ids: Optional[list[str]] = None
    link_public_ip_public_ips: Optional[list[str]] = None
    mac_addresses: Optional[list[str]] = None
    net_ids: Optional[list[str]] = None
    nic_ids: Optional[list[str]] = None
    private_dns_names: Optional[list[str]] = None
    private_ips_link_public_ip_account_ids: Optional[list[str]] = None
    private_ips_link_public_ip_public_ips: Optional[list[str]] = None
    private_ips_primary_ip: Optional[bool] = None
    private_ips_private_ips: Optional[list[str]] = None
    security_group_ids: Optional[list[str]] = None
    security_group_names: Optional[list[str]] = None
    states: Optional[list[str]] = None
    subnet_ids: Optional[list[str]] = None
    subregion_names: Optional[list[str]] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersProductType(BaseObject):
    product_type_ids: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersPublicIp(BaseObject):
    link_public_ip_ids: Optional[list[str]] = None
    nic_account_ids: Optional[list[str]] = None
    nic_ids: Optional[list[str]] = None
    placements: Optional[list[str]] = None
    private_ips: Optional[list[str]] = None
    public_ip_ids: Optional[list[str]] = None
    public_ips: Optional[list[str]] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    vm_ids: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersQuota(BaseObject):
    collections: Optional[list[str]] = None
    quota_names: Optional[list[str]] = None
    quota_types: Optional[list[str]] = None
    short_descriptions: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersRouteTable(BaseObject):
    link_route_table_ids: Optional[list[str]] = None
    link_route_table_link_route_table_ids: Optional[list[str]] = None
    link_route_table_main: Optional[bool] = None
    link_subnet_ids: Optional[list[str]] = None
    net_ids: Optional[list[str]] = None
    route_creation_methods: Optional[list[str]] = None
    route_destination_ip_ranges: Optional[list[str]] = None
    route_destination_service_ids: Optional[list[str]] = None
    route_gateway_ids: Optional[list[str]] = None
    route_nat_service_ids: Optional[list[str]] = None
    route_net_peering_ids: Optional[list[str]] = None
    route_states: Optional[list[str]] = None
    route_table_ids: Optional[list[str]] = None
    route_vm_ids: Optional[list[str]] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersSecurityGroup(BaseObject):
    account_ids: Optional[list[str]] = None
    descriptions: Optional[list[str]] = None
    inbound_rule_account_ids: Optional[list[str]] = None
    inbound_rule_from_port_ranges: Optional[list[int]] = None
    inbound_rule_ip_ranges: Optional[list[str]] = None
    inbound_rule_protocols: Optional[list[str]] = None
    inbound_rule_security_group_ids: Optional[list[str]] = None
    inbound_rule_security_group_names: Optional[list[str]] = None
    inbound_rule_to_port_ranges: Optional[list[int]] = None
    net_ids: Optional[list[str]] = None
    outbound_rule_account_ids: Optional[list[str]] = None
    outbound_rule_from_port_ranges: Optional[list[int]] = None
    outbound_rule_ip_ranges: Optional[list[str]] = None
    outbound_rule_protocols: Optional[list[str]] = None
    outbound_rule_security_group_ids: Optional[list[str]] = None
    outbound_rule_security_group_names: Optional[list[str]] = None
    outbound_rule_to_port_ranges: Optional[list[int]] = None
    security_group_ids: Optional[list[str]] = None
    security_group_names: Optional[list[str]] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersServerCertificate(BaseObject):
    paths: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersService(BaseObject):
    service_ids: Optional[list[str]] = None
    service_names: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersSnapshot(BaseObject):
    account_aliases: Optional[list[str]] = None
    account_ids: Optional[list[str]] = None
    descriptions: Optional[list[str]] = None
    permissions_to_create_volume_account_ids: Optional[list[str]] = None
    permissions_to_create_volume_global_permission: Optional[bool] = None
    progresses: Optional[list[int]] = None
    snapshot_ids: Optional[list[str]] = None
    states: Optional[list[str]] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    volume_ids: Optional[list[str]] = None
    volume_sizes: Optional[list[int]] = None


@alias(to_camelcase)
@dataclass
class FiltersSubnet(BaseObject):
    available_ips_counts: Optional[list[int]] = None
    ip_ranges: Optional[list[str]] = None
    net_ids: Optional[list[str]] = None
    states: Optional[list[str]] = None
    subnet_ids: Optional[list[str]] = None
    subregion_names: Optional[list[str]] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersSubregion(BaseObject):
    subregion_names: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersTag(BaseObject):
    keys: Optional[list[str]] = None
    resource_ids: Optional[list[str]] = None
    resource_types: Optional[list[str]] = None
    values: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersVirtualGateway(BaseObject):
    connection_types: Optional[list[str]] = None
    link_net_ids: Optional[list[str]] = None
    link_states: Optional[list[str]] = None
    states: Optional[list[str]] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    virtual_gateway_ids: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersVm(BaseObject):
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    vm_ids: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersVmType(BaseObject):
    bsu_optimized: Optional[bool] = None
    memory_sizes: Optional[list[float]] = None
    vcore_counts: Optional[list[int]] = None
    vm_type_names: Optional[list[str]] = None
    volume_counts: Optional[list[int]] = None
    volume_sizes: Optional[list[int]] = None


@alias(to_camelcase)
@dataclass
class FiltersVmsState(BaseObject):
    maintenance_event_codes: Optional[list[str]] = None
    maintenance_event_descriptions: Optional[list[str]] = None
    maintenance_events_not_after: Optional[list[str]] = None
    maintenance_events_not_before: Optional[list[str]] = None
    subregion_names: Optional[list[str]] = None
    vm_ids: Optional[list[str]] = None
    vm_states: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersVolume(BaseObject):
    creation_dates: Optional[list[str]] = None
    link_volume_delete_on_vm_deletion: Optional[bool] = None
    link_volume_device_names: Optional[list[str]] = None
    link_volume_link_dates: Optional[list[str]] = None
    link_volume_link_states: Optional[list[str]] = None
    link_volume_vm_ids: Optional[list[str]] = None
    snapshot_ids: Optional[list[str]] = None
    subregion_names: Optional[list[str]] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    volume_ids: Optional[list[str]] = None
    volume_sizes: Optional[list[int]] = None
    volume_states: Optional[list[str]] = None
    volume_types: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FiltersVpnConnection(BaseObject):
    bgp_asns: Optional[list[int]] = None
    client_gateway_ids: Optional[list[str]] = None
    connection_types: Optional[list[str]] = None
    route_destination_ip_ranges: Optional[list[str]] = None
    states: Optional[list[str]] = None
    static_routes_only: Optional[bool] = None
    tag_keys: Optional[list[str]] = None
    tag_values: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    virtual_gateway_ids: Optional[list[str]] = None
    vpn_connection_ids: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class FlexibleGpu(BaseObject):
    delete_on_vm_deletion: Optional[bool] = None
    flexible_gpu_id: Optional[str] = None
    generation: Optional[str] = None
    model_name: Optional[str] = None
    state: Optional[str] = None
    subregion_name: Optional[str] = None
    vm_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class FlexibleGpuCatalog(BaseObject):
    generations: Optional[list[str]] = None
    max_cpu: Optional[int] = None
    max_ram: Optional[int] = None
    model_name: Optional[str] = None
    v_ram: Optional[int] = None


@alias(to_camelcase)
@dataclass
class HealthCheck(BaseObject):
    check_interval: int
    healthy_threshold: int
    port: int
    protocol: str
    timeout: int
    unhealthy_threshold: int
    path: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Image(BaseObject):
    account_alias: Optional[str] = None
    account_id: Optional[str] = None
    architecture: Optional[str] = None
    block_device_mappings: Optional[list[BlockDeviceMappingImage]] = None
    creation_date: Optional[str] = None
    description: Optional[str] = None
    file_location: Optional[str] = None
    image_id: Optional[str] = None
    image_name: Optional[str] = None
    image_type: Optional[str] = None
    permissions_to_launch: Optional[PermissionsOnResource] = None
    product_codes: Optional[list[str]] = None
    root_device_name: Optional[str] = None
    root_device_type: Optional[str] = None
    state: Optional[str] = None
    state_comment: Optional[StateComment] = None
    tags: Optional[list[ResourceTag]] = None


@alias(to_camelcase)
@dataclass
class ImageExportTask(BaseObject):
    comment: Optional[str] = None
    image_id: Optional[str] = None
    osu_export: Optional[OsuExportImageExportTask] = None
    progress: Optional[int] = None
    state: Optional[str] = None
    tags: Optional[list[ResourceTag]] = None
    task_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class InternetService(BaseObject):
    internet_service_id: Optional[str] = None
    net_id: Optional[str] = None
    state: Optional[str] = None
    tags: Optional[list[ResourceTag]] = None


@alias(to_camelcase)
@dataclass
class Keypair(BaseObject):
    keypair_fingerprint: Optional[str] = None
    keypair_name: Optional[str] = None


@alias(to_camelcase)
@dataclass
class KeypairCreated(BaseObject):
    keypair_fingerprint: Optional[str] = None
    keypair_name: Optional[str] = None
    private_key: Optional[str] = None


@alias(to_camelcase)
@dataclass
class LinkNic(BaseObject):
    delete_on_vm_deletion: Optional[bool] = None
    device_number: Optional[int] = None
    link_nic_id: Optional[str] = None
    state: Optional[str] = None
    vm_account_id: Optional[str] = None
    vm_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class LinkNicLight(BaseObject):
    delete_on_vm_deletion: Optional[bool] = None
    device_number: Optional[int] = None
    link_nic_id: Optional[str] = None
    state: Optional[str] = None


@alias(to_camelcase)
@dataclass
class LinkNicToUpdate(BaseObject):
    delete_on_vm_deletion: Optional[bool] = None
    link_nic_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class LinkPublicIp(BaseObject):
    link_public_ip_id: Optional[str] = None
    public_dns_name: Optional[str] = None
    public_ip: Optional[str] = None
    public_ip_account_id: Optional[str] = None
    public_ip_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class LinkPublicIpLightForVm(BaseObject):
    public_dns_name: Optional[str] = None
    public_ip: Optional[str] = None
    public_ip_account_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class LinkRouteTable(BaseObject):
    link_route_table_id: Optional[str] = None
    main: Optional[bool] = None
    route_table_id: Optional[str] = None
    subnet_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class LinkedVolume(BaseObject):
    delete_on_vm_deletion: Optional[bool] = None
    device_name: Optional[str] = None
    state: Optional[str] = None
    vm_id: Optional[str] = None
    volume_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Listener(BaseObject):
    backend_port: Optional[int] = None
    backend_protocol: Optional[str] = None
    load_balancer_port: Optional[int] = None
    load_balancer_protocol: Optional[str] = None
    policy_names: Optional[list[str]] = None
    server_certificate_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class ListenerForCreation(BaseObject):
    backend_port: int
    load_balancer_port: int
    load_balancer_protocol: str
    backend_protocol: Optional[str] = None
    server_certificate_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class ListenerRule(BaseObject):
    action: Optional[str] = None
    host_name_pattern: Optional[str] = None
    listener_id: Optional[int] = None
    listener_rule_id: Optional[int] = None
    listener_rule_name: Optional[str] = None
    path_pattern: Optional[str] = None
    priority: Optional[int] = None
    vm_ids: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class ListenerRuleForCreation(BaseObject):
    listener_rule_name: str
    priority: int
    action: Optional[str] = None
    host_name_pattern: Optional[str] = None
    path_pattern: Optional[str] = None


@alias(to_camelcase)
@dataclass
class LoadBalancer(BaseObject):
    access_log: Optional[AccessLog] = None
    application_sticky_cookie_policies: Optional[
        list[ApplicationStickyCookiePolicy]
    ] = None
    backend_ips: Optional[list[str]] = None
    backend_vm_ids: Optional[list[str]] = None
    dns_name: Optional[str] = None
    health_check: Optional[HealthCheck] = None
    listeners: Optional[list[Listener]] = None
    load_balancer_name: Optional[str] = None
    load_balancer_sticky_cookie_policies: Optional[
        list[LoadBalancerStickyCookiePolicy]
    ] = None
    load_balancer_type: Optional[str] = None
    net_id: Optional[str] = None
    public_ip: Optional[str] = None
    security_groups: Optional[list[str]] = None
    source_security_group: Optional[SourceSecurityGroup] = None
    subnets: Optional[list[str]] = None
    subregion_names: Optional[list[str]] = None
    tags: Optional[list[ResourceTag]] = None


@alias(to_camelcase)
@dataclass
class LoadBalancerLight(BaseObject):
    load_balancer_name: str
    load_balancer_port: int


@alias(to_camelcase)
@dataclass
class LoadBalancerStickyCookiePolicy(BaseObject):
    cookie_expiration_period: Optional[int] = None
    policy_name: Optional[str] = None


@alias(to_camelcase)
@dataclass
class LoadBalancerTag(BaseObject):
    key: Optional[str] = None
    load_balancer_name: Optional[str] = None
    value: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Location(BaseObject):
    code: Optional[str] = None
    name: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Log(BaseObject):
    account_id: Optional[str] = None
    call_duration: Optional[int] = None
    query_access_key: Optional[str] = None
    query_api_name: Optional[str] = None
    query_api_version: Optional[str] = None
    query_call_name: Optional[str] = None
    query_date: Optional[str] = None
    query_header_raw: Optional[str] = None
    query_header_size: Optional[int] = None
    query_ip_address: Optional[str] = None
    query_payload_raw: Optional[str] = None
    query_payload_size: Optional[int] = None
    query_user_agent: Optional[str] = None
    request_id: Optional[str] = None
    response_size: Optional[int] = None
    response_status_code: Optional[int] = None


@alias(to_camelcase)
@dataclass
class MaintenanceEvent(BaseObject):
    code: Optional[str] = None
    description: Optional[str] = None
    not_after: Optional[str] = None
    not_before: Optional[str] = None


@alias(to_camelcase)
@dataclass
class NatService(BaseObject):
    nat_service_id: Optional[str] = None
    net_id: Optional[str] = None
    public_ips: Optional[list[PublicIpLight]] = None
    state: Optional[str] = None
    subnet_id: Optional[str] = None
    tags: Optional[list[ResourceTag]] = None


@alias(to_camelcase)
@dataclass
class Net(BaseObject):
    dhcp_options_set_id: Optional[str] = None
    ip_range: Optional[str] = None
    net_id: Optional[str] = None
    state: Optional[str] = None
    tags: Optional[list[ResourceTag]] = None
    tenancy: Optional[str] = None


@alias(to_camelcase)
@dataclass
class NetAccessPoint(BaseObject):
    net_access_point_id: Optional[str] = None
    net_id: Optional[str] = None
    route_table_ids: Optional[list[str]] = None
    service_name: Optional[str] = None
    state: Optional[str] = None
    tags: Optional[list[ResourceTag]] = None


@alias(to_camelcase)
@dataclass
class NetPeering(BaseObject):
    accepter_net: Optional[AccepterNet] = None
    net_peering_id: Optional[str] = None
    source_net: Optional[SourceNet] = None
    state: Optional[NetPeeringState] = None
    tags: Optional[list[ResourceTag]] = None


@alias(to_camelcase)
@dataclass
class NetPeeringState(BaseObject):
    message: Optional[str] = None
    name: Optional[str] = None


@alias(to_camelcase)
@dataclass
class NetToVirtualGatewayLink(BaseObject):
    net_id: Optional[str] = None
    state: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Nic(BaseObject):
    account_id: Optional[str] = None
    description: Optional[str] = None
    is_source_dest_checked: Optional[bool] = None
    link_nic: Optional[LinkNic] = None
    link_public_ip: Optional[LinkPublicIp] = None
    mac_address: Optional[str] = None
    net_id: Optional[str] = None
    nic_id: Optional[str] = None
    private_dns_name: Optional[str] = None
    private_ips: Optional[list[PrivateIp]] = None
    security_groups: Optional[list[SecurityGroupLight]] = None
    state: Optional[str] = None
    subnet_id: Optional[str] = None
    subregion_name: Optional[str] = None
    tags: Optional[list[ResourceTag]] = None


@alias(to_camelcase)
@dataclass
class NicForVmCreation(BaseObject):
    delete_on_vm_deletion: Optional[bool] = None
    description: Optional[str] = None
    device_number: Optional[int] = None
    nic_id: Optional[str] = None
    private_ips: Optional[list[PrivateIpLight]] = None
    secondary_private_ip_count: Optional[int] = None
    security_group_ids: Optional[list[str]] = None
    subnet_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class NicLight(BaseObject):
    account_id: Optional[str] = None
    description: Optional[str] = None
    is_source_dest_checked: Optional[bool] = None
    link_nic: Optional[LinkNicLight] = None
    link_public_ip: Optional[LinkPublicIpLightForVm] = None
    mac_address: Optional[str] = None
    net_id: Optional[str] = None
    nic_id: Optional[str] = None
    private_dns_name: Optional[str] = None
    private_ips: Optional[list[PrivateIpLightForVm]] = None
    security_groups: Optional[list[SecurityGroupLight]] = None
    state: Optional[str] = None
    subnet_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class OsuApiKey(BaseObject):
    api_key_id: Optional[str] = None
    secret_key: Optional[str] = None


@alias(to_camelcase)
@dataclass
class OsuExportImageExportTask(BaseObject):
    disk_image_format: str
    osu_bucket: str
    osu_manifest_url: Optional[str] = None
    osu_prefix: Optional[str] = None


@alias(to_camelcase)
@dataclass
class OsuExportSnapshotExportTask(BaseObject):
    disk_image_format: str
    osu_bucket: str
    osu_prefix: Optional[str] = None


@alias(to_camelcase)
@dataclass
class OsuExportToCreate(BaseObject):
    disk_image_format: str
    osu_bucket: str
    osu_api_key: Optional[OsuApiKey] = None
    osu_manifest_url: Optional[str] = None
    osu_prefix: Optional[str] = None


@alias(to_camelcase)
@dataclass
class PermissionsOnResource(BaseObject):
    account_ids: Optional[list[str]] = None
    global_permission: Optional[bool] = None


@alias(to_camelcase)
@dataclass
class PermissionsOnResourceCreation(BaseObject):
    additions: Optional[PermissionsOnResource] = None
    removals: Optional[PermissionsOnResource] = None


@alias(to_camelcase)
@dataclass
class Phase1Options(BaseObject):
    dpd_timeout_action: Optional[str] = None
    dpd_timeout_seconds: Optional[int] = None
    ike_versions: Optional[list[str]] = None
    phase1_dh_group_numbers: Optional[list[int]] = None
    phase1_encryption_algorithms: Optional[list[str]] = None
    phase1_integrity_algorithms: Optional[list[str]] = None
    phase1_lifetime_seconds: Optional[int] = None
    replay_window_size: Optional[int] = None
    startup_action: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Phase2Options(BaseObject):
    phase2_dh_group_numbers: Optional[list[int]] = None
    phase2_encryption_algorithms: Optional[list[str]] = None
    phase2_integrity_algorithms: Optional[list[str]] = None
    phase2_lifetime_seconds: Optional[int] = None
    pre_shared_key: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Placement(BaseObject):
    subregion_name: Optional[str] = None
    tenancy: Optional[str] = None


@alias(to_camelcase)
@dataclass
class PrivateIp(BaseObject):
    is_primary: Optional[bool] = None
    link_public_ip: Optional[LinkPublicIp] = None
    private_dns_name: Optional[str] = None
    private_ip: Optional[str] = None


@alias(to_camelcase)
@dataclass
class PrivateIpLight(BaseObject):
    is_primary: Optional[bool] = None
    private_ip: Optional[str] = None


@alias(to_camelcase)
@dataclass
class PrivateIpLightForVm(BaseObject):
    is_primary: Optional[bool] = None
    link_public_ip: Optional[LinkPublicIpLightForVm] = None
    private_dns_name: Optional[str] = None
    private_ip: Optional[str] = None


@alias(to_camelcase)
@dataclass
class ProductType(BaseObject):
    description: Optional[str] = None
    product_type_id: Optional[str] = None
    vendor: Optional[str] = None


@alias(to_camelcase)
@dataclass
class PublicIp(BaseObject):
    link_public_ip_id: Optional[str] = None
    nic_account_id: Optional[str] = None
    nic_id: Optional[str] = None
    private_ip: Optional[str] = None
    public_ip: Optional[str] = None
    public_ip_id: Optional[str] = None
    tags: Optional[list[ResourceTag]] = None
    vm_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class PublicIpLight(BaseObject):
    public_ip: Optional[str] = None
    public_ip_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Quota(BaseObject):
    account_id: Optional[str] = None
    description: Optional[str] = None
    max_value: Optional[int] = None
    name: Optional[str] = None
    quota_collection: Optional[str] = None
    short_description: Optional[str] = None
    used_value: Optional[int] = None


@alias(to_camelcase)
@dataclass
class QuotaTypes(BaseObject):
    quota_type: Optional[str] = None
    quotas: Optional[list[Quota]] = None


@alias(to_camelcase)
@dataclass
class Region(BaseObject):
    endpoint: Optional[str] = None
    region_name: Optional[str] = None


@alias(to_camelcase)
@dataclass
class ResourceLoadBalancerTag(BaseObject):
    key: Optional[str] = None


@alias(to_camelcase)
@dataclass
class ResourceTag(BaseObject):
    key: str
    value: str


@alias(to_camelcase)
@dataclass
class ResponseContext(BaseObject):
    request_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Route(BaseObject):
    creation_method: Optional[str] = None
    destination_ip_range: Optional[str] = None
    destination_service_id: Optional[str] = None
    gateway_id: Optional[str] = None
    nat_service_id: Optional[str] = None
    net_access_point_id: Optional[str] = None
    net_peering_id: Optional[str] = None
    nic_id: Optional[str] = None
    state: Optional[str] = None
    vm_account_id: Optional[str] = None
    vm_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class RouteLight(BaseObject):
    destination_ip_range: Optional[str] = None
    route_type: Optional[str] = None
    state: Optional[str] = None


@alias(to_camelcase)
@dataclass
class RoutePropagatingVirtualGateway(BaseObject):
    virtual_gateway_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class RouteTable(BaseObject):
    link_route_tables: Optional[list[LinkRouteTable]] = None
    net_id: Optional[str] = None
    route_propagating_virtual_gateways: Optional[
        list[RoutePropagatingVirtualGateway]
    ] = None
    route_table_id: Optional[str] = None
    routes: Optional[list[Route]] = None
    tags: Optional[list[ResourceTag]] = None


@alias(to_camelcase)
@dataclass
class SecurityGroup(BaseObject):
    account_id: Optional[str] = None
    description: Optional[str] = None
    inbound_rules: Optional[list[SecurityGroupRule]] = None
    net_id: Optional[str] = None
    outbound_rules: Optional[list[SecurityGroupRule]] = None
    security_group_id: Optional[str] = None
    security_group_name: Optional[str] = None
    tags: Optional[list[ResourceTag]] = None


@alias(to_camelcase)
@dataclass
class SecurityGroupLight(BaseObject):
    security_group_id: Optional[str] = None
    security_group_name: Optional[str] = None


@alias(to_camelcase)
@dataclass
class SecurityGroupRule(BaseObject):
    from_port_range: Optional[int] = None
    ip_protocol: Optional[str] = None
    ip_ranges: Optional[list[str]] = None
    security_groups_members: Optional[list[SecurityGroupsMember]] = None
    service_ids: Optional[list[str]] = None
    to_port_range: Optional[int] = None


@alias(to_camelcase)
@dataclass
class SecurityGroupsMember(BaseObject):
    account_id: Optional[str] = None
    security_group_id: Optional[str] = None
    security_group_name: Optional[str] = None


@alias(to_camelcase)
@dataclass
class ServerCertificate(BaseObject):
    expiration_date: Optional[str] = None
    id: Optional[str] = None
    name: Optional[str] = None
    path: Optional[str] = None
    upload_date: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Service(BaseObject):
    ip_ranges: Optional[list[str]] = None
    service_id: Optional[str] = None
    service_name: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Snapshot(BaseObject):
    account_alias: Optional[str] = None
    account_id: Optional[str] = None
    creation_date: Optional[str] = None
    description: Optional[str] = None
    permissions_to_create_volume: Optional[PermissionsOnResource] = None
    progress: Optional[int] = None
    snapshot_id: Optional[str] = None
    state: Optional[str] = None
    tags: Optional[list[ResourceTag]] = None
    volume_id: Optional[str] = None
    volume_size: Optional[int] = None


@alias(to_camelcase)
@dataclass
class SnapshotExportTask(BaseObject):
    comment: Optional[str] = None
    osu_export: Optional[OsuExportSnapshotExportTask] = None
    progress: Optional[int] = None
    snapshot_id: Optional[str] = None
    state: Optional[str] = None
    tags: Optional[list[ResourceTag]] = None
    task_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class SourceNet(BaseObject):
    account_id: Optional[str] = None
    ip_range: Optional[str] = None
    net_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class SourceSecurityGroup(BaseObject):
    security_group_account_id: Optional[str] = None
    security_group_name: Optional[str] = None


@alias(to_camelcase)
@dataclass
class StateComment(BaseObject):
    state_code: Optional[str] = None
    state_message: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Subnet(BaseObject):
    available_ips_count: Optional[int] = None
    ip_range: Optional[str] = None
    map_public_ip_on_launch: Optional[bool] = None
    net_id: Optional[str] = None
    state: Optional[str] = None
    subnet_id: Optional[str] = None
    subregion_name: Optional[str] = None
    tags: Optional[list[ResourceTag]] = None


@alias(to_camelcase)
@dataclass
class Subregion(BaseObject):
    region_name: Optional[str] = None
    state: Optional[str] = None
    subregion_name: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Tag(BaseObject):
    key: Optional[str] = None
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    value: Optional[str] = None


@alias(to_camelcase)
@dataclass
class VgwTelemetry(BaseObject):
    accepted_route_count: Optional[int] = None
    last_state_change_date: Optional[str] = None
    outside_ip_address: Optional[str] = None
    state: Optional[str] = None
    state_description: Optional[str] = None


@alias(to_camelcase)
@dataclass
class VirtualGateway(BaseObject):
    connection_type: Optional[str] = None
    net_to_virtual_gateway_links: Optional[list[NetToVirtualGatewayLink]] = None
    state: Optional[str] = None
    tags: Optional[list[ResourceTag]] = None
    virtual_gateway_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Vm(BaseObject, VmMixin):
    architecture: Optional[str] = None
    block_device_mappings: Optional[list[BlockDeviceMappingCreated]] = None
    bsu_optimized: Optional[bool] = None
    client_token: Optional[str] = None
    creation_date: Optional[str] = None
    deletion_protection: Optional[bool] = None
    hypervisor: Optional[str] = None
    image_id: Optional[str] = None
    is_source_dest_checked: Optional[bool] = None
    keypair_name: Optional[str] = None
    launch_number: Optional[int] = None
    net_id: Optional[str] = None
    nics: Optional[list[NicLight]] = None
    os_family: Optional[str] = None
    performance: Optional[str] = None
    placement: Optional[Placement] = None
    private_dns_name: Optional[str] = None
    private_ip: Optional[str] = None
    product_codes: Optional[list[str]] = None
    public_dns_name: Optional[str] = None
    public_ip: Optional[str] = None
    reservation_id: Optional[str] = None
    root_device_name: Optional[str] = None
    root_device_type: Optional[str] = None
    security_groups: Optional[list[SecurityGroupLight]] = None
    state: Optional[str] = None
    state_reason: Optional[str] = None
    subnet_id: Optional[str] = None
    tags: Optional[list[ResourceTag]] = None
    user_data: Optional[str] = None
    vm_id: Optional[str] = None
    vm_initiated_shutdown_behavior: Optional[str] = None
    vm_type: Optional[str] = None


@alias(to_camelcase)
@dataclass
class VmState(BaseObject):
    current_state: Optional[str] = None
    previous_state: Optional[str] = None
    vm_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class VmStates(BaseObject):
    maintenance_events: Optional[list[MaintenanceEvent]] = None
    subregion_name: Optional[str] = None
    vm_id: Optional[str] = None
    vm_state: Optional[str] = None


@alias(to_camelcase)
@dataclass
class VmType(BaseObject):
    bsu_optimized: Optional[bool] = None
    max_private_ips: Optional[int] = None
    memory_size: Optional[float] = None
    vcore_count: Optional[int] = None
    vm_type_name: Optional[str] = None
    volume_count: Optional[int] = None
    volume_size: Optional[int] = None


@alias(to_camelcase)
@dataclass
class Volume(BaseObject):
    creation_date: Optional[str] = None
    iops: Optional[int] = None
    linked_volumes: Optional[list[LinkedVolume]] = None
    size: Optional[int] = None
    snapshot_id: Optional[str] = None
    state: Optional[str] = None
    subregion_name: Optional[str] = None
    tags: Optional[list[ResourceTag]] = None
    volume_id: Optional[str] = None
    volume_type: Optional[str] = None


@alias(to_camelcase)
@dataclass
class VpnConnection(BaseObject):
    client_gateway_configuration: Optional[str] = None
    client_gateway_id: Optional[str] = None
    connection_type: Optional[str] = None
    routes: Optional[list[RouteLight]] = None
    state: Optional[str] = None
    static_routes_only: Optional[bool] = None
    tags: Optional[list[ResourceTag]] = None
    vgw_telemetries: Optional[list[VgwTelemetry]] = None
    virtual_gateway_id: Optional[str] = None
    vpn_connection_id: Optional[str] = None
    vpn_options: Optional[VpnOptions] = None


@alias(to_camelcase)
@dataclass
class VpnOptions(BaseObject):
    phase1_options: Optional[Phase1Options] = None
    phase2_options: Optional[Phase2Options] = None
    tunnel_inside_ip_range: Optional[str] = None


@alias(to_camelcase)
@dataclass
class With(BaseObject):
    account_id: Optional[bool] = None
    call_duration: Optional[bool] = None
    query_access_key: Optional[bool] = None
    query_api_name: Optional[bool] = None
    query_api_version: Optional[bool] = None
    query_call_name: Optional[bool] = None
    query_date: Optional[bool] = None
    query_header_raw: Optional[bool] = None
    query_header_size: Optional[bool] = None
    query_ip_address: Optional[bool] = None
    query_payload_raw: Optional[bool] = None
    query_payload_size: Optional[bool] = None
    query_user_agent: Optional[bool] = None
    request_id: Optional[bool] = None
    response_size: Optional[bool] = None
    response_status_code: Optional[bool] = None
