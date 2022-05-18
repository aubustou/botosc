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
    account_id: str
    ip_range: str
    net_id: str


@alias(to_camelcase)
@dataclass
class AccessKey(BaseObject):
    access_key_id: str
    creation_date: str
    last_modification_date: str
    state: str
    expiration_date: Optional[str] = None


@alias(to_camelcase)
@dataclass
class AccessKeySecretKey(BaseObject):
    access_key_id: str
    creation_date: str
    expiration_date: str
    last_modification_date: str
    secret_key: str
    state: str


@alias(to_camelcase)
@dataclass
class AccessLog(BaseObject):
    is_enabled: bool
    osu_bucket_name: str
    osu_bucket_prefix: str
    publication_interval: int


@alias(to_camelcase)
@dataclass
class Account(BaseObject):
    account_id: str
    additional_emails: list[str]
    city: str
    company_name: str
    country: str
    email: str
    first_name: str
    last_name: str
    zip_code: str
    customer_id: Optional[str] = None
    job_title: Optional[str] = None
    mobile_number: Optional[str] = None
    phone_number: Optional[str] = None
    state_province: Optional[str] = None
    vat_number: Optional[str] = None


@alias(to_camelcase)
@dataclass
class ApiAccessPolicy(BaseObject):
    max_access_key_expiration_seconds: int
    require_trusted_env: bool


@alias(to_camelcase)
@dataclass
class ApiAccessRule(BaseObject):
    api_access_rule_id: str
    ca_ids: list[str]
    cns: list[str]
    description: str
    ip_ranges: list[str]


@alias(to_camelcase)
@dataclass
class ApplicationStickyCookiePolicy(BaseObject):
    cookie_name: str
    policy_name: str


@alias(to_camelcase)
@dataclass
class BackendVmHealth(BaseObject):
    description: str
    state: str
    state_reason: str
    vm_id: str


@alias(to_camelcase)
@dataclass
class BlockDeviceMappingCreated(BaseObject):
    bsu: BsuCreated
    device_name: str


@alias(to_camelcase)
@dataclass
class BlockDeviceMappingImage(BaseObject):
    bsu: BsuToCreate
    device_name: str
    virtual_device_name: Optional[str] = None


@alias(to_camelcase)
@dataclass
class BlockDeviceMappingVmCreation(BaseObject):
    bsu: BsuToCreate
    device_name: str
    no_device: str
    virtual_device_name: str


@alias(to_camelcase)
@dataclass
class BlockDeviceMappingVmUpdate(BaseObject):
    bsu: BsuToUpdateVm
    device_name: str
    no_device: str
    virtual_device_name: str


@alias(to_camelcase)
@dataclass
class BsuCreated(BaseObject):
    delete_on_vm_deletion: bool
    link_date: str
    state: str
    volume_id: str


@alias(to_camelcase)
@dataclass
class BsuToCreate(BaseObject):
    delete_on_vm_deletion: bool
    snapshot_id: str
    volume_size: int
    volume_type: str
    iops: Optional[int] = None


@alias(to_camelcase)
@dataclass
class BsuToUpdateVm(BaseObject):
    delete_on_vm_deletion: bool
    volume_id: str


@alias(to_camelcase)
@dataclass
class Ca(BaseObject):
    ca_fingerprint: str
    ca_id: str
    description: str


@alias(to_camelcase)
@dataclass
class Catalog(BaseObject):
    entries: list[CatalogEntry]


@alias(to_camelcase)
@dataclass
class CatalogEntry(BaseObject):
    category: str
    operation: str
    service: str
    subregion_name: str
    title: str
    type: str
    unit_price: float
    flags: Optional[str] = None


@alias(to_camelcase)
@dataclass
class ClientGateway(BaseObject):
    bgp_asn: int
    client_gateway_id: str
    connection_type: str
    public_ip: str
    state: str
    tags: list[ResourceTag]


@alias(to_camelcase)
@dataclass
class ConsumptionEntry(BaseObject):
    account_id: str
    category: str
    from_date: str
    operation: str
    paying_account_id: str
    service: str
    subregion_name: str
    title: str
    to_date: str
    type: str
    value: int


@alias(to_camelcase)
@dataclass
class DhcpOptionsSet(BaseObject):
    default: bool
    dhcp_options_set_id: str
    domain_name: str
    domain_name_servers: list[str]
    tags: list[ResourceTag]
    ntp_servers: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class DirectLink(BaseObject):
    account_id: str
    bandwidth: str
    direct_link_id: str
    direct_link_name: str
    location: str
    region_name: str
    state: str


@alias(to_camelcase)
@dataclass
class DirectLinkInterface(BaseObject):
    bgp_asn: int
    bgp_key: str
    client_private_ip: str
    direct_link_interface_name: str
    outscale_private_ip: str
    virtual_gateway_id: str
    vlan: int


@alias(to_camelcase)
@dataclass
class DirectLinkInterfaces(BaseObject):
    account_id: str
    bgp_asn: int
    bgp_key: str
    client_private_ip: str
    direct_link_id: str
    direct_link_interface_id: str
    direct_link_interface_name: str
    interface_type: str
    location: str
    outscale_private_ip: str
    state: str
    virtual_gateway_id: str
    vlan: int


@alias(to_camelcase)
@dataclass
class Errors(BaseObject):
    code: str
    details: str
    type: str


@alias(to_camelcase)
@dataclass
class FiltersAccessKeys(BaseObject):
    access_key_ids: list[str]
    states: list[str]


@alias(to_camelcase)
@dataclass
class FiltersApiAccessRule(BaseObject):
    api_access_rule_ids: list[str]
    ca_ids: list[str]
    cns: list[str]
    descriptions: list[str]
    ip_ranges: list[str]


@alias(to_camelcase)
@dataclass
class FiltersApiLog(BaseObject):
    query_access_keys: list[str]
    query_api_names: list[str]
    query_call_names: list[str]
    query_date_after: str
    query_date_before: str
    query_ip_addresses: list[str]
    query_user_agents: list[str]
    request_ids: list[str]
    response_status_codes: list[int]


@alias(to_camelcase)
@dataclass
class FiltersCa(BaseObject):
    ca_fingerprints: list[str]
    ca_ids: list[str]
    descriptions: list[str]


@alias(to_camelcase)
@dataclass
class FiltersClientGateway(BaseObject):
    bgp_asns: list[int]
    client_gateway_ids: list[str]
    connection_types: list[str]
    public_ips: list[str]
    states: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@alias(to_camelcase)
@dataclass
class FiltersDhcpOptions(BaseObject):
    default: bool
    dhcp_options_set_ids: list[str]
    domain_name_servers: list[str]
    domain_names: list[str]
    ntp_servers: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@alias(to_camelcase)
@dataclass
class FiltersDirectLink(BaseObject):
    direct_link_ids: list[str]


@alias(to_camelcase)
@dataclass
class FiltersDirectLinkInterface(BaseObject):
    direct_link_ids: list[str]
    direct_link_interface_ids: list[str]


@alias(to_camelcase)
@dataclass
class FiltersExportTask(BaseObject):
    task_ids: list[str]


@alias(to_camelcase)
@dataclass
class FiltersFlexibleGpu(BaseObject):
    delete_on_vm_deletion: bool
    flexible_gpu_ids: list[str]
    generations: list[str]
    model_names: list[str]
    states: list[str]
    subregion_names: list[str]
    vm_ids: list[str]


@alias(to_camelcase)
@dataclass
class FiltersImage(BaseObject):
    account_aliases: list[str]
    account_ids: list[str]
    architectures: list[str]
    block_device_mapping_delete_on_vm_deletion: bool
    block_device_mapping_device_names: list[str]
    block_device_mapping_snapshot_ids: list[str]
    block_device_mapping_volume_sizes: list[int]
    block_device_mapping_volume_types: list[str]
    descriptions: list[str]
    file_locations: list[str]
    hypervisors: list[str]
    image_ids: list[str]
    image_names: list[str]
    permissions_to_launch_account_ids: list[str]
    permissions_to_launch_global_permission: bool
    product_codes: list[str]
    root_device_names: list[str]
    root_device_types: list[str]
    states: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]
    virtualization_types: list[str]


@alias(to_camelcase)
@dataclass
class FiltersInternetService(BaseObject):
    internet_service_ids: list[str]
    link_net_ids: list[str]
    link_states: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@alias(to_camelcase)
@dataclass
class FiltersKeypair(BaseObject):
    keypair_fingerprints: list[str]
    keypair_names: list[str]


@alias(to_camelcase)
@dataclass
class FiltersListenerRule(BaseObject):
    listener_rule_names: list[str]


@alias(to_camelcase)
@dataclass
class FiltersLoadBalancer(BaseObject):
    load_balancer_names: list[str]


@alias(to_camelcase)
@dataclass
class FiltersNatService(BaseObject):
    nat_service_ids: list[str]
    net_ids: list[str]
    states: list[str]
    subnet_ids: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@alias(to_camelcase)
@dataclass
class FiltersNet(BaseObject):
    dhcp_options_set_ids: list[str]
    ip_ranges: list[str]
    is_default: bool
    net_ids: list[str]
    states: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@alias(to_camelcase)
@dataclass
class FiltersNetAccessPoint(BaseObject):
    net_access_point_ids: list[str]
    net_ids: list[str]
    service_names: list[str]
    states: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@alias(to_camelcase)
@dataclass
class FiltersNetPeering(BaseObject):
    accepter_net_account_ids: list[str]
    accepter_net_ip_ranges: list[str]
    accepter_net_net_ids: list[str]
    net_peering_ids: list[str]
    source_net_account_ids: list[str]
    source_net_ip_ranges: list[str]
    source_net_net_ids: list[str]
    state_messages: list[str]
    state_names: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@alias(to_camelcase)
@dataclass
class FiltersNic(BaseObject):
    descriptions: list[str]
    is_source_dest_check: bool
    link_nic_delete_on_vm_deletion: bool
    link_nic_device_numbers: list[int]
    link_nic_link_nic_ids: list[str]
    link_nic_states: list[str]
    link_nic_vm_account_ids: list[str]
    link_nic_vm_ids: list[str]
    link_public_ip_account_ids: list[str]
    link_public_ip_link_public_ip_ids: list[str]
    link_public_ip_public_ip_ids: list[str]
    link_public_ip_public_ips: list[str]
    mac_addresses: list[str]
    net_ids: list[str]
    nic_ids: list[str]
    private_dns_names: list[str]
    private_ips_link_public_ip_account_ids: list[str]
    private_ips_link_public_ip_public_ips: list[str]
    private_ips_primary_ip: bool
    private_ips_private_ips: list[str]
    security_group_ids: list[str]
    security_group_names: list[str]
    states: list[str]
    subnet_ids: list[str]
    subregion_names: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@alias(to_camelcase)
@dataclass
class FiltersProductType(BaseObject):
    product_type_ids: list[str]


@alias(to_camelcase)
@dataclass
class FiltersPublicIp(BaseObject):
    link_public_ip_ids: list[str]
    nic_account_ids: list[str]
    nic_ids: list[str]
    placements: list[str]
    private_ips: list[str]
    public_ip_ids: list[str]
    public_ips: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]
    vm_ids: list[str]


@alias(to_camelcase)
@dataclass
class FiltersQuota(BaseObject):
    collections: list[str]
    quota_names: list[str]
    quota_types: list[str]
    short_descriptions: list[str]


@alias(to_camelcase)
@dataclass
class FiltersRouteTable(BaseObject):
    link_route_table_ids: list[str]
    link_route_table_link_route_table_ids: list[str]
    link_route_table_main: bool
    link_subnet_ids: list[str]
    net_ids: list[str]
    route_creation_methods: list[str]
    route_destination_ip_ranges: list[str]
    route_destination_service_ids: list[str]
    route_gateway_ids: list[str]
    route_nat_service_ids: list[str]
    route_net_peering_ids: list[str]
    route_states: list[str]
    route_table_ids: list[str]
    route_vm_ids: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@alias(to_camelcase)
@dataclass
class FiltersSecurityGroup(BaseObject):
    account_ids: list[str]
    descriptions: list[str]
    inbound_rule_account_ids: list[str]
    inbound_rule_from_port_ranges: list[int]
    inbound_rule_ip_ranges: list[str]
    inbound_rule_protocols: list[str]
    inbound_rule_security_group_ids: list[str]
    inbound_rule_security_group_names: list[str]
    inbound_rule_to_port_ranges: list[int]
    net_ids: list[str]
    outbound_rule_account_ids: list[str]
    outbound_rule_from_port_ranges: list[int]
    outbound_rule_ip_ranges: list[str]
    outbound_rule_protocols: list[str]
    outbound_rule_security_group_ids: list[str]
    outbound_rule_security_group_names: list[str]
    outbound_rule_to_port_ranges: list[int]
    security_group_ids: list[str]
    security_group_names: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@alias(to_camelcase)
@dataclass
class FiltersServerCertificate(BaseObject):
    paths: list[str]


@alias(to_camelcase)
@dataclass
class FiltersService(BaseObject):
    service_ids: list[str]
    service_names: list[str]


@alias(to_camelcase)
@dataclass
class FiltersSnapshot(BaseObject):
    account_aliases: list[str]
    account_ids: list[str]
    descriptions: list[str]
    permissions_to_create_volume_account_ids: list[str]
    permissions_to_create_volume_global_permission: bool
    progresses: list[int]
    snapshot_ids: list[str]
    states: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]
    volume_ids: list[str]
    volume_sizes: list[int]


@alias(to_camelcase)
@dataclass
class FiltersSubnet(BaseObject):
    available_ips_counts: list[int]
    ip_ranges: list[str]
    net_ids: list[str]
    states: list[str]
    subnet_ids: list[str]
    subregion_names: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@alias(to_camelcase)
@dataclass
class FiltersSubregion(BaseObject):
    subregion_names: list[str]


@alias(to_camelcase)
@dataclass
class FiltersTag(BaseObject):
    keys: list[str]
    resource_ids: list[str]
    resource_types: list[str]
    values: list[str]


@alias(to_camelcase)
@dataclass
class FiltersVirtualGateway(BaseObject):
    connection_types: list[str]
    link_net_ids: list[str]
    link_states: list[str]
    states: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]
    virtual_gateway_ids: list[str]


@alias(to_camelcase)
@dataclass
class FiltersVm(BaseObject):
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]
    vm_ids: list[str]


@alias(to_camelcase)
@dataclass
class FiltersVmType(BaseObject):
    bsu_optimized: bool
    memory_sizes: list[float]
    vcore_counts: list[int]
    vm_type_names: list[str]
    volume_counts: list[int]
    volume_sizes: list[int]


@alias(to_camelcase)
@dataclass
class FiltersVmsState(BaseObject):
    maintenance_event_codes: list[str]
    maintenance_event_descriptions: list[str]
    maintenance_events_not_after: list[str]
    maintenance_events_not_before: list[str]
    subregion_names: list[str]
    vm_ids: list[str]
    vm_states: list[str]


@alias(to_camelcase)
@dataclass
class FiltersVolume(BaseObject):
    creation_dates: list[str]
    link_volume_delete_on_vm_deletion: bool
    link_volume_device_names: list[str]
    link_volume_link_dates: list[str]
    link_volume_link_states: list[str]
    link_volume_vm_ids: list[str]
    snapshot_ids: list[str]
    subregion_names: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]
    volume_ids: list[str]
    volume_sizes: list[int]
    volume_states: list[str]
    volume_types: list[str]


@alias(to_camelcase)
@dataclass
class FiltersVpnConnection(BaseObject):
    bgp_asns: list[int]
    client_gateway_ids: list[str]
    connection_types: list[str]
    route_destination_ip_ranges: list[str]
    states: list[str]
    static_routes_only: bool
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]
    virtual_gateway_ids: list[str]
    vpn_connection_ids: list[str]


@alias(to_camelcase)
@dataclass
class FlexibleGpu(BaseObject):
    delete_on_vm_deletion: bool
    flexible_gpu_id: str
    generation: str
    model_name: str
    state: str
    subregion_name: str
    vm_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class FlexibleGpuCatalog(BaseObject):
    generations: list[str]
    max_cpu: int
    max_ram: int
    model_name: str
    v_ram: int


@alias(to_camelcase)
@dataclass
class HealthCheck(BaseObject):
    check_interval: int
    healthy_threshold: int
    path: str
    port: int
    protocol: str
    timeout: int
    unhealthy_threshold: int


@alias(to_camelcase)
@dataclass
class Image(BaseObject):
    account_id: str
    architecture: str
    block_device_mappings: list[BlockDeviceMappingImage]
    creation_date: str
    description: str
    file_location: str
    image_id: str
    image_name: str
    image_type: str
    permissions_to_launch: PermissionsOnResource
    product_codes: list[str]
    root_device_name: str
    root_device_type: str
    state: str
    state_comment: StateComment
    tags: list[ResourceTag]
    account_alias: Optional[str] = None


@alias(to_camelcase)
@dataclass
class ImageExportTask(BaseObject):
    comment: str
    image_id: str
    osu_export: OsuExportImageExportTask
    progress: int
    state: str
    tags: list[ResourceTag]
    task_id: str


@alias(to_camelcase)
@dataclass
class InternetService(BaseObject):
    internet_service_id: str
    net_id: str
    state: str
    tags: list[ResourceTag]


@alias(to_camelcase)
@dataclass
class Keypair(BaseObject):
    keypair_fingerprint: str
    keypair_name: str


@alias(to_camelcase)
@dataclass
class KeypairCreated(BaseObject):
    keypair_fingerprint: str
    keypair_name: str
    private_key: str


@alias(to_camelcase)
@dataclass
class LinkNic(BaseObject):
    delete_on_vm_deletion: bool
    device_number: int
    link_nic_id: str
    state: str
    vm_account_id: str
    vm_id: str


@alias(to_camelcase)
@dataclass
class LinkNicLight(BaseObject):
    delete_on_vm_deletion: bool
    device_number: int
    link_nic_id: str
    state: str


@alias(to_camelcase)
@dataclass
class LinkNicToUpdate(BaseObject):
    delete_on_vm_deletion: bool
    link_nic_id: str


@alias(to_camelcase)
@dataclass
class LinkPublicIp(BaseObject):
    link_public_ip_id: str
    public_dns_name: str
    public_ip: str
    public_ip_account_id: str
    public_ip_id: str


@alias(to_camelcase)
@dataclass
class LinkPublicIpLightForVm(BaseObject):
    public_dns_name: str
    public_ip: str
    public_ip_account_id: str


@alias(to_camelcase)
@dataclass
class LinkRouteTable(BaseObject):
    link_route_table_id: str
    main: bool
    route_table_id: str
    subnet_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class LinkedVolume(BaseObject):
    delete_on_vm_deletion: bool
    device_name: str
    state: str
    vm_id: str
    volume_id: str


@alias(to_camelcase)
@dataclass
class Listener(BaseObject):
    backend_port: int
    backend_protocol: str
    load_balancer_port: int
    load_balancer_protocol: str
    policy_names: list[str]
    server_certificate_id: str


@alias(to_camelcase)
@dataclass
class ListenerForCreation(BaseObject):
    backend_port: int
    backend_protocol: str
    load_balancer_port: int
    load_balancer_protocol: str
    server_certificate_id: str


@alias(to_camelcase)
@dataclass
class ListenerRule(BaseObject):
    action: str
    host_name_pattern: str
    listener_id: int
    listener_rule_id: int
    listener_rule_name: str
    path_pattern: str
    priority: int
    vm_ids: list[str]


@alias(to_camelcase)
@dataclass
class ListenerRuleForCreation(BaseObject):
    action: str
    host_name_pattern: str
    listener_rule_name: str
    path_pattern: str
    priority: int


@alias(to_camelcase)
@dataclass
class LoadBalancer(BaseObject):
    access_log: AccessLog
    application_sticky_cookie_policies: list[ApplicationStickyCookiePolicy]
    backend_ips: list[str]
    backend_vm_ids: list[str]
    dns_name: str
    health_check: HealthCheck
    listeners: list[Listener]
    load_balancer_name: str
    load_balancer_sticky_cookie_policies: list[LoadBalancerStickyCookiePolicy]
    load_balancer_type: str
    net_id: str
    public_ip: str
    security_groups: list[str]
    source_security_group: SourceSecurityGroup
    subnets: list[str]
    subregion_names: list[str]
    tags: list[ResourceTag]


@alias(to_camelcase)
@dataclass
class LoadBalancerLight(BaseObject):
    load_balancer_name: str
    load_balancer_port: int


@alias(to_camelcase)
@dataclass
class LoadBalancerStickyCookiePolicy(BaseObject):
    cookie_expiration_period: int
    policy_name: str


@alias(to_camelcase)
@dataclass
class LoadBalancerTag(BaseObject):
    key: str
    load_balancer_name: str
    value: str


@alias(to_camelcase)
@dataclass
class Location(BaseObject):
    code: str
    name: str


@alias(to_camelcase)
@dataclass
class Log(BaseObject):
    account_id: str
    call_duration: int
    query_access_key: str
    query_api_name: str
    query_api_version: str
    query_call_name: str
    query_date: str
    query_header_raw: str
    query_header_size: int
    query_ip_address: str
    query_payload_raw: str
    query_payload_size: int
    query_user_agent: str
    request_id: str
    response_size: int
    response_status_code: int


@alias(to_camelcase)
@dataclass
class MaintenanceEvent(BaseObject):
    code: str
    description: str
    not_after: str
    not_before: str


@alias(to_camelcase)
@dataclass
class NatService(BaseObject):
    nat_service_id: str
    net_id: str
    public_ips: list[PublicIpLight]
    state: str
    subnet_id: str
    tags: list[ResourceTag]


@alias(to_camelcase)
@dataclass
class Net(BaseObject):
    dhcp_options_set_id: str
    ip_range: str
    net_id: str
    state: str
    tags: list[ResourceTag]
    tenancy: str


@alias(to_camelcase)
@dataclass
class NetAccessPoint(BaseObject):
    net_access_point_id: str
    net_id: str
    route_table_ids: list[str]
    service_name: str
    state: str
    tags: list[ResourceTag]


@alias(to_camelcase)
@dataclass
class NetPeering(BaseObject):
    accepter_net: AccepterNet
    net_peering_id: str
    source_net: SourceNet
    state: NetPeeringState
    tags: list[ResourceTag]


@alias(to_camelcase)
@dataclass
class NetPeeringState(BaseObject):
    message: str
    name: str


@alias(to_camelcase)
@dataclass
class NetToVirtualGatewayLink(BaseObject):
    net_id: str
    state: str


@alias(to_camelcase)
@dataclass
class Nic(BaseObject):
    account_id: str
    description: str
    is_source_dest_checked: bool
    link_nic: LinkNic
    mac_address: str
    net_id: str
    nic_id: str
    private_dns_name: str
    private_ips: list[PrivateIp]
    security_groups: list[SecurityGroupLight]
    state: str
    subnet_id: str
    subregion_name: str
    tags: list[ResourceTag]
    link_public_ip: Optional[LinkPublicIp] = None


@alias(to_camelcase)
@dataclass
class NicForVmCreation(BaseObject):
    delete_on_vm_deletion: bool
    description: str
    device_number: int
    nic_id: str
    private_ips: list[PrivateIpLight]
    secondary_private_ip_count: int
    security_group_ids: list[str]
    subnet_id: str


@alias(to_camelcase)
@dataclass
class NicLight(BaseObject):
    account_id: str
    description: str
    is_source_dest_checked: bool
    link_nic: LinkNicLight
    link_public_ip: LinkPublicIpLightForVm
    mac_address: str
    net_id: str
    nic_id: str
    private_dns_name: str
    private_ips: list[PrivateIpLightForVm]
    security_groups: list[SecurityGroupLight]
    state: str
    subnet_id: str


@alias(to_camelcase)
@dataclass
class OsuApiKey(BaseObject):
    api_key_id: str
    secret_key: str


@alias(to_camelcase)
@dataclass
class OsuExportImageExportTask(BaseObject):
    disk_image_format: str
    osu_bucket: str
    osu_manifest_url: str
    osu_prefix: str


@alias(to_camelcase)
@dataclass
class OsuExportSnapshotExportTask(BaseObject):
    disk_image_format: str
    osu_bucket: str
    osu_prefix: str


@alias(to_camelcase)
@dataclass
class OsuExportToCreate(BaseObject):
    disk_image_format: str
    osu_api_key: OsuApiKey
    osu_bucket: str
    osu_manifest_url: str
    osu_prefix: str


@alias(to_camelcase)
@dataclass
class PermissionsOnResource(BaseObject):
    account_ids: list[str]
    global_permission: bool


@alias(to_camelcase)
@dataclass
class PermissionsOnResourceCreation(BaseObject):
    additions: PermissionsOnResource
    removals: PermissionsOnResource


@alias(to_camelcase)
@dataclass
class Phase1Options(BaseObject):
    dpd_timeout_action: str
    dpd_timeout_seconds: int
    ike_versions: list[str]
    phase1_dh_group_numbers: list[int]
    phase1_encryption_algorithms: list[str]
    phase1_integrity_algorithms: list[str]
    phase1_lifetime_seconds: int
    replay_window_size: int
    startup_action: str


@alias(to_camelcase)
@dataclass
class Phase2Options(BaseObject):
    phase2_dh_group_numbers: list[int]
    phase2_encryption_algorithms: list[str]
    phase2_integrity_algorithms: list[str]
    phase2_lifetime_seconds: int
    pre_shared_key: str


@alias(to_camelcase)
@dataclass
class Placement(BaseObject):
    subregion_name: str
    tenancy: str


@alias(to_camelcase)
@dataclass
class PrivateIp(BaseObject):
    is_primary: bool
    private_dns_name: str
    private_ip: str
    link_public_ip: Optional[LinkPublicIp] = None


@alias(to_camelcase)
@dataclass
class PrivateIpLight(BaseObject):
    is_primary: bool
    private_ip: str


@alias(to_camelcase)
@dataclass
class PrivateIpLightForVm(BaseObject):
    is_primary: bool
    link_public_ip: LinkPublicIpLightForVm
    private_dns_name: str
    private_ip: str


@alias(to_camelcase)
@dataclass
class ProductType(BaseObject):
    description: str
    product_type_id: str
    vendor: Optional[str] = None


@alias(to_camelcase)
@dataclass
class PublicIp(BaseObject):
    public_ip: str
    public_ip_id: str
    tags: list[ResourceTag]
    link_public_ip_id: Optional[str] = None
    nic_account_id: Optional[str] = None
    nic_id: Optional[str] = None
    private_ip: Optional[str] = None
    vm_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class PublicIpLight(BaseObject):
    public_ip: str
    public_ip_id: str


@alias(to_camelcase)
@dataclass
class Quota(BaseObject):
    account_id: str
    description: str
    max_value: int
    name: str
    quota_collection: str
    short_description: str
    used_value: int


@alias(to_camelcase)
@dataclass
class QuotaTypes(BaseObject):
    quota_type: str
    quotas: list[Quota]


@alias(to_camelcase)
@dataclass
class Region(BaseObject):
    endpoint: str
    region_name: str


@alias(to_camelcase)
@dataclass
class ResourceLoadBalancerTag(BaseObject):
    key: str


@alias(to_camelcase)
@dataclass
class ResourceTag(BaseObject):
    key: str
    value: str


@alias(to_camelcase)
@dataclass
class ResponseContext(BaseObject):
    request_id: str


@alias(to_camelcase)
@dataclass
class Route(BaseObject):
    creation_method: str
    destination_ip_range: str
    state: str
    destination_service_id: Optional[str] = None
    gateway_id: Optional[str] = None
    nat_service_id: Optional[str] = None
    net_access_point_id: Optional[str] = None
    net_peering_id: Optional[str] = None
    nic_id: Optional[str] = None
    vm_account_id: Optional[str] = None
    vm_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class RouteLight(BaseObject):
    destination_ip_range: str
    route_type: str
    state: str


@alias(to_camelcase)
@dataclass
class RoutePropagatingVirtualGateway(BaseObject):
    virtual_gateway_id: str


@alias(to_camelcase)
@dataclass
class RouteTable(BaseObject):
    link_route_tables: list[LinkRouteTable]
    net_id: str
    route_propagating_virtual_gateways: list[RoutePropagatingVirtualGateway]
    route_table_id: str
    routes: list[Route]
    tags: list[ResourceTag]


@alias(to_camelcase)
@dataclass
class SecurityGroup(BaseObject):
    account_id: str
    description: str
    inbound_rules: list[SecurityGroupRule]
    outbound_rules: list[SecurityGroupRule]
    security_group_id: str
    security_group_name: str
    tags: list[ResourceTag]
    net_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class SecurityGroupLight(BaseObject):
    security_group_id: str
    security_group_name: str


@alias(to_camelcase)
@dataclass
class SecurityGroupRule(BaseObject):
    from_port_range: int
    ip_protocol: str
    to_port_range: int
    ip_ranges: Optional[list[str]] = None
    security_groups_members: Optional[list[SecurityGroupsMember]] = None
    service_ids: Optional[list[str]] = None


@alias(to_camelcase)
@dataclass
class SecurityGroupsMember(BaseObject):
    account_id: str
    security_group_id: str
    security_group_name: str


@alias(to_camelcase)
@dataclass
class ServerCertificate(BaseObject):
    expiration_date: str
    id: str
    name: str
    path: str
    upload_date: str


@alias(to_camelcase)
@dataclass
class Service(BaseObject):
    ip_ranges: list[str]
    service_id: str
    service_name: str


@alias(to_camelcase)
@dataclass
class Snapshot(BaseObject):
    account_id: str
    creation_date: str
    description: str
    permissions_to_create_volume: PermissionsOnResource
    progress: int
    snapshot_id: str
    state: str
    tags: list[ResourceTag]
    volume_size: int
    account_alias: Optional[str] = None
    volume_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class SnapshotExportTask(BaseObject):
    comment: str
    osu_export: OsuExportSnapshotExportTask
    progress: int
    snapshot_id: str
    state: str
    tags: list[ResourceTag]
    task_id: str


@alias(to_camelcase)
@dataclass
class SourceNet(BaseObject):
    account_id: str
    ip_range: str
    net_id: str


@alias(to_camelcase)
@dataclass
class SourceSecurityGroup(BaseObject):
    security_group_account_id: str
    security_group_name: str


@alias(to_camelcase)
@dataclass
class StateComment(BaseObject):
    state_code: Optional[str] = None
    state_message: Optional[str] = None


@alias(to_camelcase)
@dataclass
class Subnet(BaseObject):
    available_ips_count: int
    ip_range: str
    map_public_ip_on_launch: bool
    net_id: str
    state: str
    subnet_id: str
    subregion_name: str
    tags: list[ResourceTag]


@alias(to_camelcase)
@dataclass
class Subregion(BaseObject):
    region_name: str
    state: str
    subregion_name: str


@alias(to_camelcase)
@dataclass
class Tag(BaseObject):
    key: str
    resource_id: str
    resource_type: str
    value: str


@alias(to_camelcase)
@dataclass
class VgwTelemetry(BaseObject):
    accepted_route_count: int
    last_state_change_date: str
    outside_ip_address: str
    state: str
    state_description: str


@alias(to_camelcase)
@dataclass
class VirtualGateway(BaseObject):
    connection_type: str
    net_to_virtual_gateway_links: list[NetToVirtualGatewayLink]
    state: str
    tags: list[ResourceTag]
    virtual_gateway_id: str


@alias(to_camelcase)
@dataclass
class Vm(BaseObject, VmMixin):
    architecture: str
    block_device_mappings: list[BlockDeviceMappingCreated]
    bsu_optimized: bool
    creation_date: str
    deletion_protection: bool
    hypervisor: str
    image_id: str
    is_source_dest_checked: bool
    keypair_name: str
    launch_number: int
    performance: str
    placement: Placement
    private_dns_name: str
    private_ip: str
    product_codes: list[str]
    reservation_id: str
    root_device_name: str
    root_device_type: str
    security_groups: list[SecurityGroupLight]
    state: str
    state_reason: str
    tags: list[ResourceTag]
    user_data: str
    vm_id: str
    vm_initiated_shutdown_behavior: str
    vm_type: str
    client_token: Optional[str] = None
    net_id: Optional[str] = None
    nics: Optional[list[NicLight]] = None
    os_family: Optional[str] = None
    public_dns_name: Optional[str] = None
    public_ip: Optional[str] = None
    subnet_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class VmState(BaseObject):
    current_state: str
    previous_state: str
    vm_id: str


@alias(to_camelcase)
@dataclass
class VmStates(BaseObject):
    maintenance_events: list[MaintenanceEvent]
    subregion_name: str
    vm_id: str
    vm_state: str


@alias(to_camelcase)
@dataclass
class VmType(BaseObject):
    bsu_optimized: bool
    max_private_ips: int
    memory_size: float
    vcore_count: int
    vm_type_name: str
    volume_count: int
    volume_size: Optional[int] = None


@alias(to_camelcase)
@dataclass
class Volume(BaseObject):
    creation_date: str
    linked_volumes: list[LinkedVolume]
    size: int
    state: str
    subregion_name: str
    tags: list[ResourceTag]
    volume_id: str
    volume_type: str
    iops: Optional[int] = None
    snapshot_id: Optional[str] = None


@alias(to_camelcase)
@dataclass
class VpnConnection(BaseObject):
    client_gateway_configuration: str
    client_gateway_id: str
    connection_type: str
    routes: list[RouteLight]
    state: str
    static_routes_only: bool
    tags: list[ResourceTag]
    vgw_telemetries: list[VgwTelemetry]
    virtual_gateway_id: str
    vpn_connection_id: str
    vpn_options: VpnOptions


@alias(to_camelcase)
@dataclass
class VpnOptions(BaseObject):
    phase1_options: Phase1Options
    phase2_options: Phase2Options
    tunnel_inside_ip_range: str


@alias(to_camelcase)
@dataclass
class With(BaseObject):
    account_id: bool
    call_duration: bool
    query_access_key: bool
    query_api_name: bool
    query_api_version: bool
    query_call_name: bool
    query_date: bool
    query_header_raw: bool
    query_header_size: bool
    query_ip_address: bool
    query_payload_raw: bool
    query_payload_size: bool
    query_user_agent: bool
    request_id: bool
    response_size: bool
    response_status_code: bool
