from dataclasses import dataclass


@dataclass
class AccepterNet:
    account_id: str
    ip_range: str
    net_id: str


@dataclass
class AccessKey:
    access_key_id: str
    creation_date: str
    expiration_date: str
    last_modification_date: str
    state: str


@dataclass
class AccessKeySecretKey:
    access_key_id: str
    creation_date: str
    expiration_date: str
    last_modification_date: str
    secret_key: str
    state: str


@dataclass
class AccessLog:
    is_enabled: bool
    osu_bucket_name: str
    osu_bucket_prefix: str
    publication_interval: int


@dataclass
class Account:
    account_id: str
    city: str
    company_name: str
    country: str
    customer_id: str
    email: str
    first_name: str
    job_title: str
    last_name: str
    mobile_number: str
    phone_number: str
    state_province: str
    vat_number: str
    zip_code: str


@dataclass
class ApiAccessRule:
    api_access_rule_id: str
    ca_ids: list[str]
    cns: list[str]
    description: str
    ip_ranges: list[str]


@dataclass
class ApplicationStickyCookiePolicy:
    cookie_name: str
    policy_name: str


@dataclass
class BackendVmHealth:
    description: str
    state: str
    state_reason: str
    vm_id: str


@dataclass
class BlockDeviceMappingCreated:
    bsu: "BsuCreated"
    device_name: str


@dataclass
class BlockDeviceMappingImage:
    bsu: "BsuToCreate"
    device_name: str
    virtual_device_name: str


@dataclass
class BlockDeviceMappingVmCreation:
    bsu: "BsuToCreate"
    device_name: str
    no_device: str
    virtual_device_name: str


@dataclass
class BlockDeviceMappingVmUpdate:
    bsu: "BsuToUpdateVm"
    device_name: str
    no_device: str
    virtual_device_name: str


@dataclass
class BsuCreated:
    delete_on_vm_deletion: bool
    link_date: str
    state: str
    volume_id: str


@dataclass
class BsuToCreate:
    delete_on_vm_deletion: bool
    iops: int
    snapshot_id: str
    volume_size: int
    volume_type: str


@dataclass
class BsuToUpdateVm:
    delete_on_vm_deletion: bool
    volume_id: str


@dataclass
class Ca:
    ca_fingerprint: str
    ca_id: str
    description: str


@dataclass
class ClientGateway:
    bgp_asn: int
    client_gateway_id: str
    connection_type: str
    public_ip: str
    state: str
    tags: list['ResourceTag']


@dataclass
class ConsumptionEntry:
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


@dataclass
class DhcpOptionsSet:
    default: bool
    dhcp_options_set_id: str
    domain_name: str
    domain_name_servers: list[str]
    ntp_servers: list[str]
    tags: list['ResourceTag']


@dataclass
class DirectLink:
    account_id: str
    bandwidth: str
    direct_link_id: str
    direct_link_name: str
    location: str
    region_name: str
    state: str


@dataclass
class DirectLinkInterface:
    bgp_asn: int
    bgp_key: str
    client_private_ip: str
    direct_link_interface_name: str
    outscale_private_ip: str
    virtual_gateway_id: str
    vlan: int


@dataclass
class DirectLinkInterfaces:
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


@dataclass
class Errors:
    code: str
    details: str
    type: str


@dataclass
class FiltersAccessKeys:
    access_key_ids: list[str]
    states: list[str]


@dataclass
class FiltersApiAccessRule:
    api_access_rule_ids: list[str]
    ca_ids: list[str]
    cns: list[str]
    descriptions: list[str]
    ip_ranges: list[str]


@dataclass
class FiltersApiLog:
    query_access_keys: list[str]
    query_api_names: list[str]
    query_call_names: list[str]
    query_date_after: str
    query_date_before: str
    query_ip_addresses: list[str]
    query_user_agents: list[str]
    request_ids: list[str]
    response_status_codes: list[int]


@dataclass
class FiltersCa:
    ca_fingerprints: list[str]
    ca_ids: list[str]
    descriptions: list[str]


@dataclass
class FiltersClientGateway:
    bgp_asns: list[int]
    client_gateway_ids: list[str]
    connection_types: list[str]
    public_ips: list[str]
    states: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@dataclass
class FiltersDhcpOptions:
    default: bool
    dhcp_options_set_ids: list[str]
    domain_name_servers: list[str]
    domain_names: list[str]
    ntp_servers: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@dataclass
class FiltersDirectLink:
    direct_link_ids: list[str]


@dataclass
class FiltersDirectLinkInterface:
    direct_link_ids: list[str]
    direct_link_interface_ids: list[str]


@dataclass
class FiltersExportTask:
    task_ids: list[str]


@dataclass
class FiltersFlexibleGpu:
    delete_on_vm_deletion: bool
    flexible_gpu_ids: list[str]
    generations: list[str]
    model_names: list[str]
    states: list[str]
    subregion_names: list[str]
    vm_ids: list[str]


@dataclass
class FiltersImage:
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


@dataclass
class FiltersInternetService:
    internet_service_ids: list[str]
    link_net_ids: list[str]
    link_states: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@dataclass
class FiltersKeypair:
    keypair_fingerprints: list[str]
    keypair_names: list[str]


@dataclass
class FiltersListenerRule:
    listener_rule_names: list[str]


@dataclass
class FiltersLoadBalancer:
    load_balancer_names: list[str]


@dataclass
class FiltersNatService:
    nat_service_ids: list[str]
    net_ids: list[str]
    states: list[str]
    subnet_ids: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@dataclass
class FiltersNet:
    dhcp_options_set_ids: list[str]
    ip_ranges: list[str]
    is_default: bool
    net_ids: list[str]
    states: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@dataclass
class FiltersNetAccessPoint:
    net_access_point_ids: list[str]
    net_ids: list[str]
    service_names: list[str]
    states: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@dataclass
class FiltersNetPeering:
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


@dataclass
class FiltersNic:
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


@dataclass
class FiltersProductType:
    product_type_ids: list[str]


@dataclass
class FiltersPublicIp:
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


@dataclass
class FiltersQuota:
    collections: list[str]
    quota_names: list[str]
    quota_types: list[str]
    short_descriptions: list[str]


@dataclass
class FiltersRouteTable:
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


@dataclass
class FiltersSecurityGroup:
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


@dataclass
class FiltersServerCertificate:
    paths: list[str]


@dataclass
class FiltersService:
    service_ids: list[str]
    service_names: list[str]


@dataclass
class FiltersSnapshot:
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


@dataclass
class FiltersSubnet:
    available_ips_counts: list[int]
    ip_ranges: list[str]
    net_ids: list[str]
    states: list[str]
    subnet_ids: list[str]
    subregion_names: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]


@dataclass
class FiltersSubregion:
    subregion_names: list[str]


@dataclass
class FiltersTag:
    keys: list[str]
    resource_ids: list[str]
    resource_types: list[str]
    values: list[str]


@dataclass
class FiltersVirtualGateway:
    connection_types: list[str]
    link_net_ids: list[str]
    link_states: list[str]
    states: list[str]
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]
    virtual_gateway_ids: list[str]


@dataclass
class FiltersVm:
    tag_keys: list[str]
    tag_values: list[str]
    tags: list[str]
    vm_ids: list[str]


@dataclass
class FiltersVmType:
    bsu_optimized: bool
    memory_sizes: list[float]
    vcore_counts: list[int]
    vm_type_names: list[str]
    volume_counts: list[int]
    volume_sizes: list[int]


@dataclass
class FiltersVmsState:
    maintenance_event_codes: list[str]
    maintenance_event_descriptions: list[str]
    maintenance_events_not_after: list[str]
    maintenance_events_not_before: list[str]
    subregion_names: list[str]
    vm_ids: list[str]
    vm_states: list[str]


@dataclass
class FiltersVolume:
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


@dataclass
class FiltersVpnConnection:
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


@dataclass
class FlexibleGpu:
    delete_on_vm_deletion: bool
    flexible_gpu_id: str
    generation: str
    model_name: str
    state: str
    subregion_name: str
    vm_id: str


@dataclass
class FlexibleGpuCatalog:
    generations: list[str]
    max_cpu: int
    max_ram: int
    model_name: str
    v_ram: int


@dataclass
class HealthCheck:
    check_interval: int
    healthy_threshold: int
    path: str
    port: int
    protocol: str
    timeout: int
    unhealthy_threshold: int


@dataclass
class Image:
    account_alias: str
    account_id: str
    architecture: str
    block_device_mappings: list['BlockDeviceMappingImage']
    creation_date: str
    description: str
    file_location: str
    image_id: str
    image_name: str
    image_type: str
    permissions_to_launch: "PermissionsOnResource"
    product_codes: list[str]
    root_device_name: str
    root_device_type: str
    state: str
    state_comment: "StateComment"
    tags: list['ResourceTag']


@dataclass
class ImageExportTask:
    comment: str
    image_id: str
    osu_export: "OsuExportImageExportTask"
    progress: int
    state: str
    tags: list['ResourceTag']
    task_id: str


@dataclass
class InternetService:
    internet_service_id: str
    net_id: str
    state: str
    tags: list['ResourceTag']


@dataclass
class Keypair:
    keypair_fingerprint: str
    keypair_name: str


@dataclass
class KeypairCreated:
    keypair_fingerprint: str
    keypair_name: str
    private_key: str


@dataclass
class LinkNic:
    delete_on_vm_deletion: bool
    device_number: int
    link_nic_id: str
    state: str
    vm_account_id: str
    vm_id: str


@dataclass
class LinkNicLight:
    delete_on_vm_deletion: bool
    device_number: int
    link_nic_id: str
    state: str


@dataclass
class LinkNicToUpdate:
    delete_on_vm_deletion: bool
    link_nic_id: str


@dataclass
class LinkPublicIp:
    link_public_ip_id: str
    public_dns_name: str
    public_ip: str
    public_ip_account_id: str
    public_ip_id: str


@dataclass
class LinkPublicIpLightForVm:
    public_dns_name: str
    public_ip: str
    public_ip_account_id: str


@dataclass
class LinkRouteTable:
    link_route_table_id: str
    main: bool
    route_table_id: str
    subnet_id: str


@dataclass
class LinkedVolume:
    delete_on_vm_deletion: bool
    device_name: str
    state: str
    vm_id: str
    volume_id: str


@dataclass
class Listener:
    backend_port: int
    backend_protocol: str
    load_balancer_port: int
    load_balancer_protocol: str
    policy_names: list[str]
    server_certificate_id: str


@dataclass
class ListenerForCreation:
    backend_port: int
    backend_protocol: str
    load_balancer_port: int
    load_balancer_protocol: str
    server_certificate_id: str


@dataclass
class ListenerRule:
    action: str
    host_name_pattern: str
    listener_id: int
    listener_rule_id: int
    listener_rule_name: str
    path_pattern: str
    priority: int
    vm_ids: list[str]


@dataclass
class ListenerRuleForCreation:
    action: str
    host_name_pattern: str
    listener_rule_name: str
    path_pattern: str
    priority: int


@dataclass
class LoadBalancer:
    access_log: "AccessLog"
    application_sticky_cookie_policies: list['ApplicationStickyCookiePolicy']
    backend_vm_ids: list[str]
    dns_name: str
    health_check: "HealthCheck"
    listeners: list['Listener']
    load_balancer_name: str
    load_balancer_sticky_cookie_policies: list['LoadBalancerStickyCookiePolicy']
    load_balancer_type: str
    net_id: str
    security_groups: list[str]
    source_security_group: "SourceSecurityGroup"
    subnets: list[str]
    subregion_names: list[str]
    tags: list['ResourceTag']


@dataclass
class LoadBalancerLight:
    load_balancer_name: str
    load_balancer_port: int


@dataclass
class LoadBalancerStickyCookiePolicy:
    policy_name: str


@dataclass
class LoadBalancerTag:
    key: str
    load_balancer_name: str
    value: str


@dataclass
class Location:
    code: str
    name: str


@dataclass
class Log:
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


@dataclass
class MaintenanceEvent:
    code: str
    description: str
    not_after: str
    not_before: str


@dataclass
class NatService:
    nat_service_id: str
    net_id: str
    public_ips: list['PublicIpLight']
    state: str
    subnet_id: str
    tags: list['ResourceTag']


@dataclass
class Net:
    dhcp_options_set_id: str
    ip_range: str
    net_id: str
    state: str
    tags: list['ResourceTag']
    tenancy: str


@dataclass
class NetAccessPoint:
    net_access_point_id: str
    net_id: str
    route_table_ids: list[str]
    service_name: str
    state: str
    tags: list['ResourceTag']


@dataclass
class NetPeering:
    accepter_net: "AccepterNet"
    net_peering_id: str
    source_net: "SourceNet"
    state: "NetPeeringState"
    tags: list['ResourceTag']


@dataclass
class NetPeeringState:
    message: str
    name: str


@dataclass
class NetToVirtualGatewayLink:
    net_id: str
    state: str


@dataclass
class Nic:
    account_id: str
    description: str
    is_source_dest_checked: bool
    link_nic: "LinkNic"
    link_public_ip: "LinkPublicIp"
    mac_address: str
    net_id: str
    nic_id: str
    private_dns_name: str
    private_ips: list['PrivateIp']
    security_groups: list['SecurityGroupLight']
    state: str
    subnet_id: str
    subregion_name: str
    tags: list['ResourceTag']


@dataclass
class NicForVmCreation:
    delete_on_vm_deletion: bool
    description: str
    device_number: int
    nic_id: str
    private_ips: list['PrivateIpLight']
    secondary_private_ip_count: int
    security_group_ids: list[str]
    subnet_id: str


@dataclass
class NicLight:
    account_id: str
    description: str
    is_source_dest_checked: bool
    link_nic: "LinkNicLight"
    link_public_ip: "LinkPublicIpLightForVm"
    mac_address: str
    net_id: str
    nic_id: str
    private_dns_name: str
    private_ips: list['PrivateIpLightForVm']
    security_groups: list['SecurityGroupLight']
    state: str
    subnet_id: str


@dataclass
class OsuApiKey:
    api_key_id: str
    secret_key: str


@dataclass
class OsuExportImageExportTask:
    disk_image_format: str
    osu_bucket: str
    osu_manifest_url: str
    osu_prefix: str


@dataclass
class OsuExportSnapshotExportTask:
    disk_image_format: str
    osu_bucket: str
    osu_prefix: str


@dataclass
class OsuExportToCreate:
    disk_image_format: str
    osu_api_key: "OsuApiKey"
    osu_bucket: str
    osu_manifest_url: str
    osu_prefix: str


@dataclass
class PermissionsOnResource:
    account_ids: list[str]
    global_permission: bool


@dataclass
class PermissionsOnResourceCreation:
    additions: "PermissionsOnResource"
    removals: "PermissionsOnResource"


@dataclass
class Phase1Options:
    dpd_timeout_action: str
    dpd_timeout_seconds: int
    ike_versions: list[str]
    phase1_dh_group_numbers: list[int]
    phase1_encryption_algorithms: list[str]
    phase1_integrity_algorithms: list[str]
    phase1_lifetime_seconds: int
    replay_window_size: int
    startup_action: str


@dataclass
class Phase2Options:
    phase2_dh_group_numbers: list[int]
    phase2_encryption_algorithms: list[str]
    phase2_integrity_algorithms: list[str]
    phase2_lifetime_seconds: int
    pre_shared_key: str


@dataclass
class Placement:
    subregion_name: str
    tenancy: str


@dataclass
class PrivateIp:
    is_primary: bool
    link_public_ip: "LinkPublicIp"
    private_dns_name: str
    private_ip: str


@dataclass
class PrivateIpLight:
    is_primary: bool
    private_ip: str


@dataclass
class PrivateIpLightForVm:
    is_primary: bool
    link_public_ip: "LinkPublicIpLightForVm"
    private_dns_name: str
    private_ip: str


@dataclass
class ProductType:
    description: str
    product_type_id: str
    vendor: str


@dataclass
class PublicIp:
    link_public_ip_id: str
    nic_account_id: str
    nic_id: str
    private_ip: str
    public_ip: str
    public_ip_id: str
    tags: list['ResourceTag']
    vm_id: str


@dataclass
class PublicIpLight:
    public_ip: str
    public_ip_id: str


@dataclass
class Quota:
    account_id: str
    description: str
    max_value: int
    name: str
    quota_collection: str
    short_description: str
    used_value: int


@dataclass
class QuotaTypes:
    quota_type: str
    quotas: list['Quota']


@dataclass
class Region:
    endpoint: str
    region_name: str


@dataclass
class ResourceLoadBalancerTag:
    key: str


@dataclass
class ResourceTag:
    key: str
    value: str


@dataclass
class ResponseContext:
    request_id: str


@dataclass
class Route:
    creation_method: str
    destination_ip_range: str
    destination_service_id: str
    gateway_id: str
    nat_service_id: str
    net_access_point_id: str
    net_peering_id: str
    nic_id: str
    state: str
    vm_account_id: str
    vm_id: str


@dataclass
class RouteLight:
    destination_ip_range: str
    route_type: str
    state: str


@dataclass
class RoutePropagatingVirtualGateway:
    virtual_gateway_id: str


@dataclass
class RouteTable:
    link_route_tables: list['LinkRouteTable']
    net_id: str
    route_propagating_virtual_gateways: list['RoutePropagatingVirtualGateway']
    route_table_id: str
    routes: list['Route']
    tags: list['ResourceTag']


@dataclass
class SecurityGroup:
    account_id: str
    description: str
    inbound_rules: list['SecurityGroupRule']
    net_id: str
    outbound_rules: list['SecurityGroupRule']
    security_group_id: str
    security_group_name: str
    tags: list['ResourceTag']


@dataclass
class SecurityGroupLight:
    security_group_id: str
    security_group_name: str


@dataclass
class SecurityGroupRule:
    from_port_range: int
    ip_protocol: str
    ip_ranges: list[str]
    security_groups_members: list['SecurityGroupsMember']
    service_ids: list[str]
    to_port_range: int


@dataclass
class SecurityGroupsMember:
    account_id: str
    security_group_id: str
    security_group_name: str


@dataclass
class ServerCertificate:
    expiration_date: str
    id: str
    name: str
    path: str
    upload_date: str


@dataclass
class Service:
    ip_ranges: list[str]
    service_id: str
    service_name: str


@dataclass
class Snapshot:
    account_alias: str
    account_id: str
    description: str
    permissions_to_create_volume: "PermissionsOnResource"
    progress: int
    snapshot_id: str
    state: str
    tags: list['ResourceTag']
    volume_id: str
    volume_size: int


@dataclass
class SnapshotExportTask:
    comment: str
    osu_export: "OsuExportSnapshotExportTask"
    progress: int
    snapshot_id: str
    state: str
    tags: list['ResourceTag']
    task_id: str


@dataclass
class SourceNet:
    account_id: str
    ip_range: str
    net_id: str


@dataclass
class SourceSecurityGroup:
    security_group_account_id: str
    security_group_name: str


@dataclass
class StateComment:
    state_code: str
    state_message: str


@dataclass
class Subnet:
    available_ips_count: int
    ip_range: str
    map_public_ip_on_launch: bool
    net_id: str
    state: str
    subnet_id: str
    subregion_name: str
    tags: list['ResourceTag']


@dataclass
class Subregion:
    region_name: str
    state: str
    subregion_name: str


@dataclass
class Tag:
    key: str
    resource_id: str
    resource_type: str
    value: str


@dataclass
class VirtualGateway:
    connection_type: str
    net_to_virtual_gateway_links: list['NetToVirtualGatewayLink']
    state: str
    tags: list['ResourceTag']
    virtual_gateway_id: str


@dataclass
class Vm:
    architecture: str
    block_device_mappings: list['BlockDeviceMappingCreated']
    bsu_optimized: bool
    client_token: str
    deletion_protection: bool
    hypervisor: str
    image_id: str
    is_source_dest_checked: bool
    keypair_name: str
    launch_number: int
    net_id: str
    nics: list['NicLight']
    os_family: str
    performance: str
    placement: "Placement"
    private_dns_name: str
    private_ip: str
    product_codes: list[str]
    public_dns_name: str
    public_ip: str
    reservation_id: str
    root_device_name: str
    root_device_type: str
    security_groups: list['SecurityGroupLight']
    state: str
    state_reason: str
    subnet_id: str
    tags: list['ResourceTag']
    user_data: str
    vm_id: str
    vm_initiated_shutdown_behavior: str
    vm_type: str


@dataclass
class VmState:
    current_state: str
    previous_state: str
    vm_id: str


@dataclass
class VmStates:
    maintenance_events: list['MaintenanceEvent']
    subregion_name: str
    vm_id: str
    vm_state: str


@dataclass
class VmType:
    bsu_optimized: bool
    max_private_ips: int
    memory_size: float
    vcore_count: int
    vm_type_name: str
    volume_count: int
    volume_size: int


@dataclass
class Volume:
    iops: int
    linked_volumes: list['LinkedVolume']
    size: int
    snapshot_id: str
    state: str
    subregion_name: str
    tags: list['ResourceTag']
    volume_id: str
    volume_type: str


@dataclass
class VpnConnection:
    client_gateway_configuration: str
    client_gateway_id: str
    connection_type: str
    routes: list['RouteLight']
    state: str
    static_routes_only: bool
    tags: list['ResourceTag']
    virtual_gateway_id: str
    vpn_connection_id: str
    vpn_options: "VpnOptions"


@dataclass
class VpnOptions:
    phase1_options: "Phase1Options"
    phase2_options: "Phase2Options"
    tunnel_inside_ip_range: str


@dataclass
class With:
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


