from typing import Optional

from apischema import deserialize, serialize

from botosc.model import (
    AccessKey,
    AccessKeySecretKey,
    AccessLog,
    Account,
    ApiAccessPolicy,
    ApiAccessRule,
    BackendVmHealth,
    BlockDeviceMappingImage,
    BlockDeviceMappingVmCreation,
    BlockDeviceMappingVmUpdate,
    Ca,
    Catalog,
    ClientGateway,
    ConsumptionEntry,
    DhcpOptionsSet,
    DirectLink,
    DirectLinkInterface,
    DirectLinkInterfaces,
    FiltersAccessKeys,
    FiltersApiAccessRule,
    FiltersApiLog,
    FiltersCa,
    FiltersClientGateway,
    FiltersDhcpOptions,
    FiltersDirectLink,
    FiltersDirectLinkInterface,
    FiltersExportTask,
    FiltersFlexibleGpu,
    FiltersImage,
    FiltersInternetService,
    FiltersKeypair,
    FiltersListenerRule,
    FiltersLoadBalancer,
    FiltersNatService,
    FiltersNet,
    FiltersNetAccessPoint,
    FiltersNetPeering,
    FiltersNic,
    FiltersProductType,
    FiltersPublicIp,
    FiltersQuota,
    FiltersRouteTable,
    FiltersSecurityGroup,
    FiltersServerCertificate,
    FiltersService,
    FiltersSnapshot,
    FiltersSubnet,
    FiltersSubregion,
    FiltersTag,
    FiltersVirtualGateway,
    FiltersVm,
    FiltersVmsState,
    FiltersVmType,
    FiltersVolume,
    FiltersVpnConnection,
    FlexibleGpu,
    FlexibleGpuCatalog,
    HealthCheck,
    Image,
    ImageExportTask,
    InternetService,
    Keypair,
    KeypairCreated,
    LinkNicToUpdate,
    ListenerForCreation,
    ListenerRule,
    ListenerRuleForCreation,
    LoadBalancer,
    LoadBalancerLight,
    LoadBalancerTag,
    Location,
    Log,
    NatService,
    Net,
    NetAccessPoint,
    NetPeering,
    NetToVirtualGatewayLink,
    Nic,
    NicForVmCreation,
    OsuExportToCreate,
    PermissionsOnResourceCreation,
    Placement,
    PrivateIpLight,
    ProductType,
    PublicIp,
    QuotaTypes,
    Region,
    ResourceLoadBalancerTag,
    ResourceTag,
    RouteTable,
    SecurityGroup,
    SecurityGroupRule,
    ServerCertificate,
    Service,
    Snapshot,
    SnapshotExportTask,
    Subnet,
    Subregion,
    Tag,
    VirtualGateway,
    Vm,
    VmState,
    VmStates,
    VmType,
    Volume,
    VpnConnection,
    VpnOptions,
    With,
)

from .utils import OSCCall_ as OSCCall


class Connector(OSCCall):
    def accept_net_peering(
        self, net_peering_id: str, dry_run: Optional[bool] = None
    ) -> NetPeering:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "AcceptNetPeering", NetPeeringId=net_peering_id, **params
        )

        item = deserialize(NetPeering, response["NetPeering"])

        item._connection = self

        return item

    def check_authentication(
        self, login: str, password: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "CheckAuthentication", Login=login, Password=password, **params
        )
        return

    def create_access_key(
        self, dry_run: Optional[bool] = None, expiration_date: Optional[str] = None
    ) -> AccessKeySecretKey:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if expiration_date is not None:
            params["ExpirationDate"] = expiration_date
        response = self.make_request("CreateAccessKey", **params)

        item = deserialize(AccessKeySecretKey, response["AccessKey"])

        item._connection = self

        return item

    def create_account(
        self,
        city: str,
        company_name: str,
        country: str,
        customer_id: str,
        email: str,
        first_name: str,
        last_name: str,
        zip_code: str,
        additional_emails: Optional[list[str]] = None,
        dry_run: Optional[bool] = None,
        job_title: Optional[str] = None,
        mobile_number: Optional[str] = None,
        phone_number: Optional[str] = None,
        state_province: Optional[str] = None,
        vat_number: Optional[str] = None,
    ) -> Account:
        params = {}
        if additional_emails is not None:
            params["AdditionalEmails"] = additional_emails
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
        response = self.make_request(
            "CreateAccount",
            City=city,
            CompanyName=company_name,
            Country=country,
            CustomerId=customer_id,
            Email=email,
            FirstName=first_name,
            LastName=last_name,
            ZipCode=zip_code,
            **params
        )

        item = deserialize(Account, response["Account"])

        item._connection = self

        return item

    def create_api_access_rule(
        self,
        ca_ids: Optional[list[str]] = None,
        cns: Optional[list[str]] = None,
        description: Optional[str] = None,
        dry_run: Optional[bool] = None,
        ip_ranges: Optional[list[str]] = None,
    ) -> ApiAccessRule:
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
        response = self.make_request("CreateApiAccessRule", **params)

        item = deserialize(ApiAccessRule, response["ApiAccessRule"])

        item._connection = self

        return item

    def create_ca(
        self,
        ca_pem: str,
        description: Optional[str] = None,
        dry_run: Optional[bool] = None,
    ) -> Ca:
        params = {}
        if description is not None:
            params["Description"] = description
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("CreateCa", CaPem=ca_pem, **params)

        item = deserialize(Ca, response["Ca"])

        item._connection = self

        return item

    def create_client_gateway(
        self,
        bgp_asn: int,
        connection_type: str,
        public_ip: str,
        dry_run: Optional[bool] = None,
    ) -> ClientGateway:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "CreateClientGateway",
            BgpAsn=bgp_asn,
            ConnectionType=connection_type,
            PublicIp=public_ip,
            **params
        )

        item = deserialize(ClientGateway, response["ClientGateway"])

        item._connection = self

        return item

    def create_dhcp_options(
        self,
        domain_name: Optional[str] = None,
        domain_name_servers: Optional[list[str]] = None,
        dry_run: Optional[bool] = None,
        ntp_servers: Optional[list[str]] = None,
    ) -> DhcpOptionsSet:
        params = {}
        if domain_name is not None:
            params["DomainName"] = domain_name
        if domain_name_servers is not None:
            params["DomainNameServers"] = domain_name_servers
        if dry_run is not None:
            params["DryRun"] = dry_run
        if ntp_servers is not None:
            params["NtpServers"] = ntp_servers
        response = self.make_request("CreateDhcpOptions", **params)

        item = deserialize(DhcpOptionsSet, response["DhcpOptionsSet"])

        item._connection = self

        return item

    def create_direct_link(
        self,
        bandwidth: str,
        direct_link_name: str,
        location: str,
        dry_run: Optional[bool] = None,
    ) -> DirectLink:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "CreateDirectLink",
            Bandwidth=bandwidth,
            DirectLinkName=direct_link_name,
            Location=location,
            **params
        )

        item = deserialize(DirectLink, response["DirectLink"])

        item._connection = self

        return item

    def create_direct_link_interface(
        self,
        direct_link_id: str,
        direct_link_interface: "DirectLinkInterface",
        dry_run: Optional[bool] = None,
    ) -> DirectLinkInterfaces:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "CreateDirectLinkInterface",
            DirectLinkId=direct_link_id,
            DirectLinkInterface=serialize(direct_link_interface),
            **params
        )

        item = deserialize(DirectLinkInterfaces, response["DirectLinkInterface"])

        item._connection = self

        return item

    def create_flexible_gpu(
        self,
        model_name: str,
        subregion_name: str,
        delete_on_vm_deletion: Optional[bool] = None,
        dry_run: Optional[bool] = None,
        generation: Optional[str] = None,
    ) -> FlexibleGpu:
        params = {}
        if delete_on_vm_deletion is not None:
            params["DeleteOnVmDeletion"] = delete_on_vm_deletion
        if dry_run is not None:
            params["DryRun"] = dry_run
        if generation is not None:
            params["Generation"] = generation
        response = self.make_request(
            "CreateFlexibleGpu",
            ModelName=model_name,
            SubregionName=subregion_name,
            **params
        )

        item = deserialize(FlexibleGpu, response["FlexibleGpu"])

        item._connection = self

        return item

    def create_image(
        self,
        architecture: Optional[str] = None,
        block_device_mappings: Optional[list["BlockDeviceMappingImage"]] = None,
        description: Optional[str] = None,
        dry_run: Optional[bool] = None,
        file_location: Optional[str] = None,
        image_name: Optional[str] = None,
        no_reboot: Optional[bool] = None,
        root_device_name: Optional[str] = None,
        source_image_id: Optional[str] = None,
        source_region_name: Optional[str] = None,
        vm_id: Optional[str] = None,
    ) -> Image:
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
        response = self.make_request("CreateImage", **params)

        item = deserialize(Image, response["Image"])

        item._connection = self

        return item

    def create_image_export_task(
        self,
        image_id: str,
        osu_export: "OsuExportToCreate",
        dry_run: Optional[bool] = None,
    ) -> ImageExportTask:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "CreateImageExportTask",
            ImageId=image_id,
            OsuExport=serialize(osu_export),
            **params
        )

        item = deserialize(ImageExportTask, response["ImageExportTask"])

        item._connection = self

        return item

    def create_internet_service(
        self, dry_run: Optional[bool] = None
    ) -> InternetService:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("CreateInternetService", **params)

        item = deserialize(InternetService, response["InternetService"])

        item._connection = self

        return item

    def create_keypair(
        self,
        keypair_name: str,
        dry_run: Optional[bool] = None,
        public_key: Optional[str] = None,
    ) -> KeypairCreated:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if public_key is not None:
            params["PublicKey"] = public_key
        response = self.make_request(
            "CreateKeypair", KeypairName=keypair_name, **params
        )

        item = deserialize(KeypairCreated, response["Keypair"])

        item._connection = self

        return item

    def create_listener_rule(
        self,
        listener: "LoadBalancerLight",
        listener_rule: "ListenerRuleForCreation",
        vm_ids: list[str],
        dry_run: Optional[bool] = None,
    ) -> ListenerRule:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "CreateListenerRule",
            Listener=serialize(listener),
            ListenerRule=serialize(listener_rule),
            VmIds=vm_ids,
            **params
        )

        item = deserialize(ListenerRule, response["ListenerRule"])

        item._connection = self

        return item

    def create_load_balancer(
        self,
        listeners: list["ListenerForCreation"],
        load_balancer_name: str,
        dry_run: Optional[bool] = None,
        load_balancer_type: Optional[str] = None,
        public_ip: Optional[str] = None,
        security_groups: Optional[list[str]] = None,
        subnets: Optional[list[str]] = None,
        subregion_names: Optional[list[str]] = None,
        tags: Optional[list["ResourceTag"]] = None,
    ) -> LoadBalancer:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if load_balancer_type is not None:
            params["LoadBalancerType"] = load_balancer_type
        if public_ip is not None:
            params["PublicIp"] = public_ip
        if security_groups is not None:
            params["SecurityGroups"] = security_groups
        if subnets is not None:
            params["Subnets"] = subnets
        if subregion_names is not None:
            params["SubregionNames"] = subregion_names
        if tags is not None:
            params["Tags"] = tags
        response = self.make_request(
            "CreateLoadBalancer",
            Listeners=listeners,
            LoadBalancerName=load_balancer_name,
            **params
        )

        item = deserialize(LoadBalancer, response["LoadBalancer"])

        item._connection = self

        return item

    def create_load_balancer_listeners(
        self,
        listeners: list["ListenerForCreation"],
        load_balancer_name: str,
        dry_run: Optional[bool] = None,
    ) -> LoadBalancer:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "CreateLoadBalancerListeners",
            Listeners=listeners,
            LoadBalancerName=load_balancer_name,
            **params
        )

        item = deserialize(LoadBalancer, response["LoadBalancer"])

        item._connection = self

        return item

    def create_load_balancer_policy(
        self,
        load_balancer_name: str,
        policy_name: str,
        policy_type: str,
        cookie_expiration_period: Optional[int] = None,
        cookie_name: Optional[str] = None,
        dry_run: Optional[bool] = None,
    ) -> LoadBalancer:
        params = {}
        if cookie_expiration_period is not None:
            params["CookieExpirationPeriod"] = cookie_expiration_period
        if cookie_name is not None:
            params["CookieName"] = cookie_name
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "CreateLoadBalancerPolicy",
            LoadBalancerName=load_balancer_name,
            PolicyName=policy_name,
            PolicyType=policy_type,
            **params
        )

        item = deserialize(LoadBalancer, response["LoadBalancer"])

        item._connection = self

        return item

    def create_load_balancer_tags(
        self,
        load_balancer_names: list[str],
        tags: list["ResourceTag"],
        dry_run: Optional[bool] = None,
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "CreateLoadBalancerTags",
            LoadBalancerNames=load_balancer_names,
            Tags=tags,
            **params
        )
        return

    def create_nat_service(
        self, public_ip_id: str, subnet_id: str, dry_run: Optional[bool] = None
    ) -> NatService:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "CreateNatService", PublicIpId=public_ip_id, SubnetId=subnet_id, **params
        )

        item = deserialize(NatService, response["NatService"])

        item._connection = self

        return item

    def create_net(
        self,
        ip_range: str,
        dry_run: Optional[bool] = None,
        tenancy: Optional[str] = None,
    ) -> Net:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if tenancy is not None:
            params["Tenancy"] = tenancy
        response = self.make_request("CreateNet", IpRange=ip_range, **params)

        item = deserialize(Net, response["Net"])

        item._connection = self

        return item

    def create_net_access_point(
        self,
        net_id: str,
        service_name: str,
        dry_run: Optional[bool] = None,
        route_table_ids: Optional[list[str]] = None,
    ) -> NetAccessPoint:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if route_table_ids is not None:
            params["RouteTableIds"] = route_table_ids
        response = self.make_request(
            "CreateNetAccessPoint", NetId=net_id, ServiceName=service_name, **params
        )

        item = deserialize(NetAccessPoint, response["NetAccessPoint"])

        item._connection = self

        return item

    def create_net_peering(
        self, accepter_net_id: str, source_net_id: str, dry_run: Optional[bool] = None
    ) -> NetPeering:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "CreateNetPeering",
            AccepterNetId=accepter_net_id,
            SourceNetId=source_net_id,
            **params
        )

        item = deserialize(NetPeering, response["NetPeering"])

        item._connection = self

        return item

    def create_nic(
        self,
        subnet_id: str,
        description: Optional[str] = None,
        dry_run: Optional[bool] = None,
        private_ips: Optional[list["PrivateIpLight"]] = None,
        security_group_ids: Optional[list[str]] = None,
    ) -> Nic:
        params = {}
        if description is not None:
            params["Description"] = description
        if dry_run is not None:
            params["DryRun"] = dry_run
        if private_ips is not None:
            params["PrivateIps"] = private_ips
        if security_group_ids is not None:
            params["SecurityGroupIds"] = security_group_ids
        response = self.make_request("CreateNic", SubnetId=subnet_id, **params)

        item = deserialize(Nic, response["Nic"])

        item._connection = self

        return item

    def create_public_ip(self, dry_run: Optional[bool] = None) -> PublicIp:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("CreatePublicIp", **params)

        item = deserialize(PublicIp, response["PublicIp"])

        item._connection = self

        return item

    def create_route(
        self,
        destination_ip_range: str,
        route_table_id: str,
        dry_run: Optional[bool] = None,
        gateway_id: Optional[str] = None,
        nat_service_id: Optional[str] = None,
        net_peering_id: Optional[str] = None,
        nic_id: Optional[str] = None,
        vm_id: Optional[str] = None,
    ) -> RouteTable:
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
        response = self.make_request(
            "CreateRoute",
            DestinationIpRange=destination_ip_range,
            RouteTableId=route_table_id,
            **params
        )

        item = deserialize(RouteTable, response["RouteTable"])

        item._connection = self

        return item

    def create_route_table(
        self, net_id: str, dry_run: Optional[bool] = None
    ) -> RouteTable:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("CreateRouteTable", NetId=net_id, **params)

        item = deserialize(RouteTable, response["RouteTable"])

        item._connection = self

        return item

    def create_security_group(
        self,
        description: str,
        security_group_name: str,
        dry_run: Optional[bool] = None,
        net_id: Optional[str] = None,
    ) -> SecurityGroup:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if net_id is not None:
            params["NetId"] = net_id
        response = self.make_request(
            "CreateSecurityGroup",
            Description=description,
            SecurityGroupName=security_group_name,
            **params
        )

        item = deserialize(SecurityGroup, response["SecurityGroup"])

        item._connection = self

        return item

    def create_security_group_rule(
        self,
        flow: str,
        security_group_id: str,
        dry_run: Optional[bool] = None,
        from_port_range: Optional[int] = None,
        ip_protocol: Optional[str] = None,
        ip_range: Optional[str] = None,
        rules: Optional[list["SecurityGroupRule"]] = None,
        security_group_account_id_to_link: Optional[str] = None,
        security_group_name_to_link: Optional[str] = None,
        to_port_range: Optional[int] = None,
    ) -> SecurityGroup:
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
        response = self.make_request(
            "CreateSecurityGroupRule",
            Flow=flow,
            SecurityGroupId=security_group_id,
            **params
        )

        item = deserialize(SecurityGroup, response["SecurityGroup"])

        item._connection = self

        return item

    def create_server_certificate(
        self,
        body: str,
        name: str,
        private_key: str,
        chain: Optional[str] = None,
        dry_run: Optional[bool] = None,
        path: Optional[str] = None,
    ) -> ServerCertificate:
        params = {}
        if chain is not None:
            params["Chain"] = chain
        if dry_run is not None:
            params["DryRun"] = dry_run
        if path is not None:
            params["Path"] = path
        response = self.make_request(
            "CreateServerCertificate",
            Body=body,
            Name=name,
            PrivateKey=private_key,
            **params
        )

        item = deserialize(ServerCertificate, response["ServerCertificate"])

        item._connection = self

        return item

    def create_snapshot(
        self,
        description: Optional[str] = None,
        dry_run: Optional[bool] = None,
        file_location: Optional[str] = None,
        snapshot_size: Optional[int] = None,
        source_region_name: Optional[str] = None,
        source_snapshot_id: Optional[str] = None,
        volume_id: Optional[str] = None,
    ) -> Snapshot:
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
        response = self.make_request("CreateSnapshot", **params)

        item = deserialize(Snapshot, response["Snapshot"])

        item._connection = self

        return item

    def create_snapshot_export_task(
        self,
        osu_export: "OsuExportToCreate",
        snapshot_id: str,
        dry_run: Optional[bool] = None,
    ) -> SnapshotExportTask:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "CreateSnapshotExportTask",
            OsuExport=serialize(osu_export),
            SnapshotId=snapshot_id,
            **params
        )

        item = deserialize(SnapshotExportTask, response["SnapshotExportTask"])

        item._connection = self

        return item

    def create_subnet(
        self,
        ip_range: str,
        net_id: str,
        dry_run: Optional[bool] = None,
        subregion_name: Optional[str] = None,
    ) -> Subnet:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if subregion_name is not None:
            params["SubregionName"] = subregion_name
        response = self.make_request(
            "CreateSubnet", IpRange=ip_range, NetId=net_id, **params
        )

        item = deserialize(Subnet, response["Subnet"])

        item._connection = self

        return item

    def create_tags(
        self,
        resource_ids: list[str],
        tags: list["ResourceTag"],
        dry_run: Optional[bool] = None,
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "CreateTags", ResourceIds=resource_ids, Tags=tags, **params
        )
        return

    def create_virtual_gateway(
        self, connection_type: str, dry_run: Optional[bool] = None
    ) -> VirtualGateway:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "CreateVirtualGateway", ConnectionType=connection_type, **params
        )

        item = deserialize(VirtualGateway, response["VirtualGateway"])

        item._connection = self

        return item

    def create_vms(
        self,
        image_id: str,
        block_device_mappings: Optional[list["BlockDeviceMappingVmCreation"]] = None,
        boot_on_creation: Optional[bool] = None,
        bsu_optimized: Optional[bool] = None,
        client_token: Optional[str] = None,
        deletion_protection: Optional[bool] = None,
        dry_run: Optional[bool] = None,
        keypair_name: Optional[str] = None,
        max_vms_count: Optional[int] = None,
        min_vms_count: Optional[int] = None,
        nics: Optional[list["NicForVmCreation"]] = None,
        performance: Optional[str] = None,
        placement: Optional["Placement"] = None,
        private_ips: Optional[list[str]] = None,
        security_group_ids: Optional[list[str]] = None,
        security_groups: Optional[list[str]] = None,
        subnet_id: Optional[str] = None,
        user_data: Optional[str] = None,
        vm_initiated_shutdown_behavior: Optional[str] = None,
        vm_type: Optional[str] = None,
    ) -> list[Vm]:
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
            params["Placement"] = serialize(placement)
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
        response = self.make_request("CreateVms", ImageId=image_id, **params)

        items = [deserialize(Vm, x) for x in response["Vms"]]

        for item in items:
            item._connection = self

        return items

    def create_volume(
        self,
        subregion_name: str,
        dry_run: Optional[bool] = None,
        iops: Optional[int] = None,
        size: Optional[int] = None,
        snapshot_id: Optional[str] = None,
        volume_type: Optional[str] = None,
    ) -> Volume:
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
        response = self.make_request(
            "CreateVolume", SubregionName=subregion_name, **params
        )

        item = deserialize(Volume, response["Volume"])

        item._connection = self

        return item

    def create_vpn_connection(
        self,
        client_gateway_id: str,
        connection_type: str,
        virtual_gateway_id: str,
        dry_run: Optional[bool] = None,
        static_routes_only: Optional[bool] = None,
    ) -> VpnConnection:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if static_routes_only is not None:
            params["StaticRoutesOnly"] = static_routes_only
        response = self.make_request(
            "CreateVpnConnection",
            ClientGatewayId=client_gateway_id,
            ConnectionType=connection_type,
            VirtualGatewayId=virtual_gateway_id,
            **params
        )

        item = deserialize(VpnConnection, response["VpnConnection"])

        item._connection = self

        return item

    def create_vpn_connection_route(
        self,
        destination_ip_range: str,
        vpn_connection_id: str,
        dry_run: Optional[bool] = None,
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "CreateVpnConnectionRoute",
            DestinationIpRange=destination_ip_range,
            VpnConnectionId=vpn_connection_id,
            **params
        )
        return

    def delete_access_key(
        self, access_key_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteAccessKey", AccessKeyId=access_key_id, **params
        )
        return

    def delete_api_access_rule(
        self, api_access_rule_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteApiAccessRule", ApiAccessRuleId=api_access_rule_id, **params
        )
        return

    def delete_ca(self, ca_id: str, dry_run: Optional[bool] = None) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("DeleteCa", CaId=ca_id, **params)
        return

    def delete_client_gateway(
        self, client_gateway_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteClientGateway", ClientGatewayId=client_gateway_id, **params
        )
        return

    def delete_dhcp_options(
        self, dhcp_options_set_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteDhcpOptions", DhcpOptionsSetId=dhcp_options_set_id, **params
        )
        return

    def delete_direct_link(
        self, direct_link_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteDirectLink", DirectLinkId=direct_link_id, **params
        )
        return

    def delete_direct_link_interface(
        self, direct_link_interface_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteDirectLinkInterface",
            DirectLinkInterfaceId=direct_link_interface_id,
            **params
        )
        return

    def delete_export_task(
        self, export_task_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteExportTask", ExportTaskId=export_task_id, **params
        )
        return

    def delete_flexible_gpu(
        self, flexible_gpu_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteFlexibleGpu", FlexibleGpuId=flexible_gpu_id, **params
        )
        return

    def delete_image(self, image_id: str, dry_run: Optional[bool] = None) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("DeleteImage", ImageId=image_id, **params)
        return

    def delete_internet_service(
        self, internet_service_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteInternetService", InternetServiceId=internet_service_id, **params
        )
        return

    def delete_keypair(self, keypair_name: str, dry_run: Optional[bool] = None) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteKeypair", KeypairName=keypair_name, **params
        )
        return

    def delete_listener_rule(
        self, listener_rule_name: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteListenerRule", ListenerRuleName=listener_rule_name, **params
        )
        return

    def delete_load_balancer(
        self, load_balancer_name: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteLoadBalancer", LoadBalancerName=load_balancer_name, **params
        )
        return

    def delete_load_balancer_listeners(
        self,
        load_balancer_name: str,
        load_balancer_ports: list[int],
        dry_run: Optional[bool] = None,
    ) -> LoadBalancer:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteLoadBalancerListeners",
            LoadBalancerName=load_balancer_name,
            LoadBalancerPorts=load_balancer_ports,
            **params
        )

        item = deserialize(LoadBalancer, response["LoadBalancer"])

        item._connection = self

        return item

    def delete_load_balancer_policy(
        self, load_balancer_name: str, policy_name: str, dry_run: Optional[bool] = None
    ) -> LoadBalancer:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteLoadBalancerPolicy",
            LoadBalancerName=load_balancer_name,
            PolicyName=policy_name,
            **params
        )

        item = deserialize(LoadBalancer, response["LoadBalancer"])

        item._connection = self

        return item

    def delete_load_balancer_tags(
        self,
        load_balancer_names: list[str],
        tags: list["ResourceLoadBalancerTag"],
        dry_run: Optional[bool] = None,
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteLoadBalancerTags",
            LoadBalancerNames=load_balancer_names,
            Tags=tags,
            **params
        )
        return

    def delete_nat_service(
        self, nat_service_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteNatService", NatServiceId=nat_service_id, **params
        )
        return

    def delete_net(self, net_id: str, dry_run: Optional[bool] = None) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("DeleteNet", NetId=net_id, **params)
        return

    def delete_net_access_point(
        self, net_access_point_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteNetAccessPoint", NetAccessPointId=net_access_point_id, **params
        )
        return

    def delete_net_peering(
        self, net_peering_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteNetPeering", NetPeeringId=net_peering_id, **params
        )
        return

    def delete_nic(self, nic_id: str, dry_run: Optional[bool] = None) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("DeleteNic", NicId=nic_id, **params)
        return

    def delete_public_ip(
        self,
        dry_run: Optional[bool] = None,
        public_ip: Optional[str] = None,
        public_ip_id: Optional[str] = None,
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if public_ip is not None:
            params["PublicIp"] = public_ip
        if public_ip_id is not None:
            params["PublicIpId"] = public_ip_id
        response = self.make_request("DeletePublicIp", **params)
        return

    def delete_route(
        self,
        destination_ip_range: str,
        route_table_id: str,
        dry_run: Optional[bool] = None,
    ) -> RouteTable:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteRoute",
            DestinationIpRange=destination_ip_range,
            RouteTableId=route_table_id,
            **params
        )

        item = deserialize(RouteTable, response["RouteTable"])

        item._connection = self

        return item

    def delete_route_table(
        self, route_table_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteRouteTable", RouteTableId=route_table_id, **params
        )
        return

    def delete_security_group(
        self,
        dry_run: Optional[bool] = None,
        security_group_id: Optional[str] = None,
        security_group_name: Optional[str] = None,
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if security_group_id is not None:
            params["SecurityGroupId"] = security_group_id
        if security_group_name is not None:
            params["SecurityGroupName"] = security_group_name
        response = self.make_request("DeleteSecurityGroup", **params)
        return

    def delete_security_group_rule(
        self,
        flow: str,
        security_group_id: str,
        dry_run: Optional[bool] = None,
        from_port_range: Optional[int] = None,
        ip_protocol: Optional[str] = None,
        ip_range: Optional[str] = None,
        rules: Optional[list["SecurityGroupRule"]] = None,
        security_group_account_id_to_unlink: Optional[str] = None,
        security_group_name_to_unlink: Optional[str] = None,
        to_port_range: Optional[int] = None,
    ) -> SecurityGroup:
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
            params[
                "SecurityGroupAccountIdToUnlink"
            ] = security_group_account_id_to_unlink
        if security_group_name_to_unlink is not None:
            params["SecurityGroupNameToUnlink"] = security_group_name_to_unlink
        if to_port_range is not None:
            params["ToPortRange"] = to_port_range
        response = self.make_request(
            "DeleteSecurityGroupRule",
            Flow=flow,
            SecurityGroupId=security_group_id,
            **params
        )

        item = deserialize(SecurityGroup, response["SecurityGroup"])

        item._connection = self

        return item

    def delete_server_certificate(
        self, name: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("DeleteServerCertificate", Name=name, **params)
        return

    def delete_snapshot(self, snapshot_id: str, dry_run: Optional[bool] = None) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("DeleteSnapshot", SnapshotId=snapshot_id, **params)
        return

    def delete_subnet(self, subnet_id: str, dry_run: Optional[bool] = None) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("DeleteSubnet", SubnetId=subnet_id, **params)
        return

    def delete_tags(
        self,
        resource_ids: list[str],
        tags: list["ResourceTag"],
        dry_run: Optional[bool] = None,
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteTags", ResourceIds=resource_ids, Tags=tags, **params
        )
        return

    def delete_virtual_gateway(
        self, virtual_gateway_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteVirtualGateway", VirtualGatewayId=virtual_gateway_id, **params
        )
        return

    def delete_vms(
        self, vm_ids: list[str], dry_run: Optional[bool] = None
    ) -> list[VmState]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("DeleteVms", VmIds=vm_ids, **params)

        items = [deserialize(VmState, x) for x in response["Vms"]]

        for item in items:
            item._connection = self

        return items

    def delete_volume(self, volume_id: str, dry_run: Optional[bool] = None) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("DeleteVolume", VolumeId=volume_id, **params)
        return

    def delete_vpn_connection(
        self, vpn_connection_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteVpnConnection", VpnConnectionId=vpn_connection_id, **params
        )
        return

    def delete_vpn_connection_route(
        self,
        destination_ip_range: str,
        vpn_connection_id: str,
        dry_run: Optional[bool] = None,
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeleteVpnConnectionRoute",
            DestinationIpRange=destination_ip_range,
            VpnConnectionId=vpn_connection_id,
            **params
        )
        return

    def deregister_vms_in_load_balancer(
        self,
        backend_vm_ids: list[str],
        load_balancer_name: str,
        dry_run: Optional[bool] = None,
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "DeregisterVmsInLoadBalancer",
            BackendVmIds=backend_vm_ids,
            LoadBalancerName=load_balancer_name,
            **params
        )
        return

    def link_flexible_gpu(
        self, flexible_gpu_id: str, vm_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "LinkFlexibleGpu", FlexibleGpuId=flexible_gpu_id, VmId=vm_id, **params
        )
        return

    def link_internet_service(
        self, internet_service_id: str, net_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "LinkInternetService",
            InternetServiceId=internet_service_id,
            NetId=net_id,
            **params
        )
        return

    def link_load_balancer_backend_machines(
        self,
        load_balancer_name: str,
        backend_ips: Optional[list[str]] = None,
        backend_vm_ids: Optional[list[str]] = None,
        dry_run: Optional[bool] = None,
    ) -> None:
        params = {}
        if backend_ips is not None:
            params["BackendIps"] = backend_ips
        if backend_vm_ids is not None:
            params["BackendVmIds"] = backend_vm_ids
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "LinkLoadBalancerBackendMachines",
            LoadBalancerName=load_balancer_name,
            **params
        )
        return

    def link_nic(
        self,
        device_number: int,
        nic_id: str,
        vm_id: str,
        dry_run: Optional[bool] = None,
    ) -> str:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "LinkNic", DeviceNumber=device_number, NicId=nic_id, VmId=vm_id, **params
        )

        item = deserialize(str, response["LinkNicId"])

        return item

    def link_private_ips(
        self,
        nic_id: str,
        allow_relink: Optional[bool] = None,
        dry_run: Optional[bool] = None,
        private_ips: Optional[list[str]] = None,
        secondary_private_ip_count: Optional[int] = None,
    ) -> None:
        params = {}
        if allow_relink is not None:
            params["AllowRelink"] = allow_relink
        if dry_run is not None:
            params["DryRun"] = dry_run
        if private_ips is not None:
            params["PrivateIps"] = private_ips
        if secondary_private_ip_count is not None:
            params["SecondaryPrivateIpCount"] = secondary_private_ip_count
        response = self.make_request("LinkPrivateIps", NicId=nic_id, **params)
        return

    def link_public_ip(
        self,
        allow_relink: Optional[bool] = None,
        dry_run: Optional[bool] = None,
        nic_id: Optional[str] = None,
        private_ip: Optional[str] = None,
        public_ip: Optional[str] = None,
        public_ip_id: Optional[str] = None,
        vm_id: Optional[str] = None,
    ) -> str:
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
        response = self.make_request("LinkPublicIp", **params)

        item = deserialize(str, response["LinkPublicIpId"])

        return item

    def link_route_table(
        self, route_table_id: str, subnet_id: str, dry_run: Optional[bool] = None
    ) -> str:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "LinkRouteTable", RouteTableId=route_table_id, SubnetId=subnet_id, **params
        )

        item = deserialize(str, response["LinkRouteTableId"])

        return item

    def link_virtual_gateway(
        self, net_id: str, virtual_gateway_id: str, dry_run: Optional[bool] = None
    ) -> NetToVirtualGatewayLink:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "LinkVirtualGateway",
            NetId=net_id,
            VirtualGatewayId=virtual_gateway_id,
            **params
        )

        item = deserialize(NetToVirtualGatewayLink, response["NetToVirtualGatewayLink"])

        item._connection = self

        return item

    def link_volume(
        self,
        device_name: str,
        vm_id: str,
        volume_id: str,
        dry_run: Optional[bool] = None,
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "LinkVolume",
            DeviceName=device_name,
            VmId=vm_id,
            VolumeId=volume_id,
            **params
        )
        return

    def read_access_keys(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersAccessKeys"] = None,
    ) -> list[AccessKey]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadAccessKeys", **params)

        items = [deserialize(AccessKey, x) for x in response["AccessKeys"]]

        for item in items:
            item._connection = self

        return items

    def read_accounts(self, dry_run: Optional[bool] = None) -> list[Account]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("ReadAccounts", **params)

        items = [deserialize(Account, x) for x in response["Accounts"]]

        for item in items:
            item._connection = self

        return items

    def read_admin_password(self, vm_id: str, dry_run: Optional[bool] = None) -> str:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("ReadAdminPassword", VmId=vm_id, **params)

        item = deserialize(str, response["AdminPassword"])

        return item

    def read_api_access_policy(self, dry_run: Optional[bool] = None) -> ApiAccessPolicy:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("ReadApiAccessPolicy", **params)

        item = deserialize(ApiAccessPolicy, response["ApiAccessPolicy"])

        item._connection = self

        return item

    def read_api_access_rules(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersApiAccessRule"] = None,
    ) -> list[ApiAccessRule]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadApiAccessRules", **params)

        items = [deserialize(ApiAccessRule, x) for x in response["ApiAccessRules"]]

        for item in items:
            item._connection = self

        return items

    def read_api_logs(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersApiLog"] = None,
        next_page_token: Optional[str] = None,
        results_per_page: Optional[int] = None,
        with_: Optional["With"] = None,
    ) -> list[Log]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        if next_page_token is not None:
            params["NextPageToken"] = next_page_token
        if results_per_page is not None:
            params["ResultsPerPage"] = results_per_page
        if with_ is not None:
            params["With_"] = serialize(with_)
        response = self.make_request("ReadApiLogs", **params)

        items = [deserialize(Log, x) for x in response["Logs"]]

        for item in items:
            item._connection = self

        return items

    def read_cas(
        self, dry_run: Optional[bool] = None, filters: Optional["FiltersCa"] = None
    ) -> list[Ca]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadCas", **params)

        items = [deserialize(Ca, x) for x in response["Cas"]]

        for item in items:
            item._connection = self

        return items

    def read_catalog(self, dry_run: Optional[bool] = None) -> Catalog:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("ReadCatalog", **params)

        item = deserialize(Catalog, response["Catalog"])

        item._connection = self

        return item

    def read_client_gateways(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersClientGateway"] = None,
    ) -> list[ClientGateway]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadClientGateways", **params)

        items = [deserialize(ClientGateway, x) for x in response["ClientGateways"]]

        for item in items:
            item._connection = self

        return items

    def read_console_output(self, vm_id: str, dry_run: Optional[bool] = None) -> str:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("ReadConsoleOutput", VmId=vm_id, **params)

        item = deserialize(str, response["ConsoleOutput"])

        return item

    def read_consumption_account(
        self, from_date: str, to_date: str, dry_run: Optional[bool] = None
    ) -> list[ConsumptionEntry]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "ReadConsumptionAccount", FromDate=from_date, ToDate=to_date, **params
        )

        items = [
            deserialize(ConsumptionEntry, x) for x in response["ConsumptionEntries"]
        ]

        for item in items:
            item._connection = self

        return items

    def read_dhcp_options(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersDhcpOptions"] = None,
    ) -> list[DhcpOptionsSet]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadDhcpOptions", **params)

        items = [deserialize(DhcpOptionsSet, x) for x in response["DhcpOptionsSets"]]

        for item in items:
            item._connection = self

        return items

    def read_direct_link_interfaces(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersDirectLinkInterface"] = None,
    ) -> list[DirectLinkInterfaces]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadDirectLinkInterfaces", **params)

        items = [
            deserialize(DirectLinkInterfaces, x)
            for x in response["DirectLinkInterfaces"]
        ]

        for item in items:
            item._connection = self

        return items

    def read_direct_links(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersDirectLink"] = None,
    ) -> list[DirectLink]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadDirectLinks", **params)

        items = [deserialize(DirectLink, x) for x in response["DirectLinks"]]

        for item in items:
            item._connection = self

        return items

    def read_flexible_gpu_catalog(
        self, dry_run: Optional[bool] = None
    ) -> list[FlexibleGpuCatalog]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("ReadFlexibleGpuCatalog", **params)

        items = [
            deserialize(FlexibleGpuCatalog, x) for x in response["FlexibleGpuCatalog"]
        ]

        for item in items:
            item._connection = self

        return items

    def read_flexible_gpus(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersFlexibleGpu"] = None,
    ) -> list[FlexibleGpu]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadFlexibleGpus", **params)

        items = [deserialize(FlexibleGpu, x) for x in response["FlexibleGpus"]]

        for item in items:
            item._connection = self

        return items

    def read_image_export_tasks(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersExportTask"] = None,
    ) -> list[ImageExportTask]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadImageExportTasks", **params)

        items = [deserialize(ImageExportTask, x) for x in response["ImageExportTasks"]]

        for item in items:
            item._connection = self

        return items

    def read_images(
        self, dry_run: Optional[bool] = None, filters: Optional["FiltersImage"] = None
    ) -> list[Image]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadImages", **params)

        items = [deserialize(Image, x) for x in response["Images"]]

        for item in items:
            item._connection = self

        return items

    def read_internet_services(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersInternetService"] = None,
    ) -> list[InternetService]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadInternetServices", **params)

        items = [deserialize(InternetService, x) for x in response["InternetServices"]]

        for item in items:
            item._connection = self

        return items

    def read_keypairs(
        self, dry_run: Optional[bool] = None, filters: Optional["FiltersKeypair"] = None
    ) -> list[Keypair]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadKeypairs", **params)

        items = [deserialize(Keypair, x) for x in response["Keypairs"]]

        for item in items:
            item._connection = self

        return items

    def read_listener_rules(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersListenerRule"] = None,
    ) -> list[ListenerRule]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadListenerRules", **params)

        items = [deserialize(ListenerRule, x) for x in response["ListenerRules"]]

        for item in items:
            item._connection = self

        return items

    def read_load_balancer_tags(
        self, load_balancer_names: list[str], dry_run: Optional[bool] = None
    ) -> list[LoadBalancerTag]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "ReadLoadBalancerTags", LoadBalancerNames=load_balancer_names, **params
        )

        items = [deserialize(LoadBalancerTag, x) for x in response["Tags"]]

        for item in items:
            item._connection = self

        return items

    def read_load_balancers(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersLoadBalancer"] = None,
    ) -> list[LoadBalancer]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadLoadBalancers", **params)

        items = [deserialize(LoadBalancer, x) for x in response["LoadBalancers"]]

        for item in items:
            item._connection = self

        return items

    def read_locations(self, dry_run: Optional[bool] = None) -> list[Location]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("ReadLocations", **params)

        items = [deserialize(Location, x) for x in response["Locations"]]

        for item in items:
            item._connection = self

        return items

    def read_nat_services(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersNatService"] = None,
    ) -> list[NatService]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadNatServices", **params)

        items = [deserialize(NatService, x) for x in response["NatServices"]]

        for item in items:
            item._connection = self

        return items

    def read_net_access_point_services(
        self, dry_run: Optional[bool] = None, filters: Optional["FiltersService"] = None
    ) -> list[Service]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadNetAccessPointServices", **params)

        items = [deserialize(Service, x) for x in response["Services"]]

        for item in items:
            item._connection = self

        return items

    def read_net_access_points(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersNetAccessPoint"] = None,
    ) -> list[NetAccessPoint]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadNetAccessPoints", **params)

        items = [deserialize(NetAccessPoint, x) for x in response["NetAccessPoints"]]

        for item in items:
            item._connection = self

        return items

    def read_net_peerings(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersNetPeering"] = None,
    ) -> list[NetPeering]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadNetPeerings", **params)

        items = [deserialize(NetPeering, x) for x in response["NetPeerings"]]

        for item in items:
            item._connection = self

        return items

    def read_nets(
        self, dry_run: Optional[bool] = None, filters: Optional["FiltersNet"] = None
    ) -> list[Net]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadNets", **params)

        items = [deserialize(Net, x) for x in response["Nets"]]

        for item in items:
            item._connection = self

        return items

    def read_nics(
        self, dry_run: Optional[bool] = None, filters: Optional["FiltersNic"] = None
    ) -> list[Nic]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadNics", **params)

        items = [deserialize(Nic, x) for x in response["Nics"]]

        for item in items:
            item._connection = self

        return items

    def read_product_types(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersProductType"] = None,
    ) -> list[ProductType]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadProductTypes", **params)

        items = [deserialize(ProductType, x) for x in response["ProductTypes"]]

        for item in items:
            item._connection = self

        return items

    def read_public_catalog(self, dry_run: Optional[bool] = None) -> Catalog:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("ReadPublicCatalog", **params)

        item = deserialize(Catalog, response["Catalog"])

        item._connection = self

        return item

    def read_public_ip_ranges(self, dry_run: Optional[bool] = None) -> list[str]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("ReadPublicIpRanges", **params)

        items = [deserialize(str, x) for x in response["PublicIps"]]

        return items

    def read_public_ips(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersPublicIp"] = None,
    ) -> list[PublicIp]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadPublicIps", **params)

        items = [deserialize(PublicIp, x) for x in response["PublicIps"]]

        for item in items:
            item._connection = self

        return items

    def read_quotas(
        self, dry_run: Optional[bool] = None, filters: Optional["FiltersQuota"] = None
    ) -> list[QuotaTypes]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadQuotas", **params)

        items = [deserialize(QuotaTypes, x) for x in response["QuotaTypes"]]

        for item in items:
            item._connection = self

        return items

    def read_regions(self, dry_run: Optional[bool] = None) -> list[Region]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("ReadRegions", **params)

        items = [deserialize(Region, x) for x in response["Regions"]]

        for item in items:
            item._connection = self

        return items

    def read_route_tables(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersRouteTable"] = None,
    ) -> list[RouteTable]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadRouteTables", **params)

        items = [deserialize(RouteTable, x) for x in response["RouteTables"]]

        for item in items:
            item._connection = self

        return items

    def read_secret_access_key(
        self, access_key_id: str, dry_run: Optional[bool] = None
    ) -> AccessKeySecretKey:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "ReadSecretAccessKey", AccessKeyId=access_key_id, **params
        )

        item = deserialize(AccessKeySecretKey, response["AccessKey"])

        item._connection = self

        return item

    def read_security_groups(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersSecurityGroup"] = None,
    ) -> list[SecurityGroup]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadSecurityGroups", **params)

        items = [deserialize(SecurityGroup, x) for x in response["SecurityGroups"]]

        for item in items:
            item._connection = self

        return items

    def read_server_certificates(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersServerCertificate"] = None,
    ) -> list[ServerCertificate]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadServerCertificates", **params)

        items = [
            deserialize(ServerCertificate, x) for x in response["ServerCertificates"]
        ]

        for item in items:
            item._connection = self

        return items

    def read_snapshot_export_tasks(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersExportTask"] = None,
    ) -> list[SnapshotExportTask]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadSnapshotExportTasks", **params)

        items = [
            deserialize(SnapshotExportTask, x) for x in response["SnapshotExportTasks"]
        ]

        for item in items:
            item._connection = self

        return items

    def read_snapshots(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersSnapshot"] = None,
    ) -> list[Snapshot]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadSnapshots", **params)

        items = [deserialize(Snapshot, x) for x in response["Snapshots"]]

        for item in items:
            item._connection = self

        return items

    def read_subnets(
        self, dry_run: Optional[bool] = None, filters: Optional["FiltersSubnet"] = None
    ) -> list[Subnet]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadSubnets", **params)

        items = [deserialize(Subnet, x) for x in response["Subnets"]]

        for item in items:
            item._connection = self

        return items

    def read_subregions(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersSubregion"] = None,
    ) -> list[Subregion]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadSubregions", **params)

        items = [deserialize(Subregion, x) for x in response["Subregions"]]

        for item in items:
            item._connection = self

        return items

    def read_tags(
        self, dry_run: Optional[bool] = None, filters: Optional["FiltersTag"] = None
    ) -> list[Tag]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadTags", **params)

        items = [deserialize(Tag, x) for x in response["Tags"]]

        for item in items:
            item._connection = self

        return items

    def read_virtual_gateways(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersVirtualGateway"] = None,
    ) -> list[VirtualGateway]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadVirtualGateways", **params)

        items = [deserialize(VirtualGateway, x) for x in response["VirtualGateways"]]

        for item in items:
            item._connection = self

        return items

    def read_vm_types(
        self, dry_run: Optional[bool] = None, filters: Optional["FiltersVmType"] = None
    ) -> list[VmType]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadVmTypes", **params)

        items = [deserialize(VmType, x) for x in response["VmTypes"]]

        for item in items:
            item._connection = self

        return items

    def read_vms(
        self, dry_run: Optional[bool] = None, filters: Optional["FiltersVm"] = None
    ) -> list[Vm]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadVms", **params)

        items = [deserialize(Vm, x) for x in response["Vms"]]

        for item in items:
            item._connection = self

        return items

    def read_vms_health(
        self,
        load_balancer_name: str,
        backend_vm_ids: Optional[list[str]] = None,
        dry_run: Optional[bool] = None,
    ) -> list[BackendVmHealth]:
        params = {}
        if backend_vm_ids is not None:
            params["BackendVmIds"] = backend_vm_ids
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "ReadVmsHealth", LoadBalancerName=load_balancer_name, **params
        )

        items = [deserialize(BackendVmHealth, x) for x in response["BackendVmHealth"]]

        for item in items:
            item._connection = self

        return items

    def read_vms_state(
        self,
        all_vms: Optional[bool] = None,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersVmsState"] = None,
    ) -> list[VmStates]:
        params = {}
        if all_vms is not None:
            params["AllVms"] = all_vms
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadVmsState", **params)

        items = [deserialize(VmStates, x) for x in response["VmStates"]]

        for item in items:
            item._connection = self

        return items

    def read_volumes(
        self, dry_run: Optional[bool] = None, filters: Optional["FiltersVolume"] = None
    ) -> list[Volume]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadVolumes", **params)

        items = [deserialize(Volume, x) for x in response["Volumes"]]

        for item in items:
            item._connection = self

        return items

    def read_vpn_connections(
        self,
        dry_run: Optional[bool] = None,
        filters: Optional["FiltersVpnConnection"] = None,
    ) -> list[VpnConnection]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if filters is not None:
            params["Filters"] = serialize(filters)
        response = self.make_request("ReadVpnConnections", **params)

        items = [deserialize(VpnConnection, x) for x in response["VpnConnections"]]

        for item in items:
            item._connection = self

        return items

    def reboot_vms(self, vm_ids: list[str], dry_run: Optional[bool] = None) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("RebootVms", VmIds=vm_ids, **params)
        return

    def register_vms_in_load_balancer(
        self,
        backend_vm_ids: list[str],
        load_balancer_name: str,
        dry_run: Optional[bool] = None,
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "RegisterVmsInLoadBalancer",
            BackendVmIds=backend_vm_ids,
            LoadBalancerName=load_balancer_name,
            **params
        )
        return

    def reject_net_peering(
        self, net_peering_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "RejectNetPeering", NetPeeringId=net_peering_id, **params
        )
        return

    def reset_account_password(
        self, password: str, token: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "ResetAccountPassword", Password=password, Token=token, **params
        )
        return

    def send_reset_password_email(
        self, email: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("SendResetPasswordEmail", Email=email, **params)
        return

    def start_vms(
        self, vm_ids: list[str], dry_run: Optional[bool] = None
    ) -> list[VmState]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("StartVms", VmIds=vm_ids, **params)

        items = [deserialize(VmState, x) for x in response["Vms"]]

        for item in items:
            item._connection = self

        return items

    def stop_vms(
        self,
        vm_ids: list[str],
        dry_run: Optional[bool] = None,
        force_stop: Optional[bool] = None,
    ) -> list[VmState]:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if force_stop is not None:
            params["ForceStop"] = force_stop
        response = self.make_request("StopVms", VmIds=vm_ids, **params)

        items = [deserialize(VmState, x) for x in response["Vms"]]

        for item in items:
            item._connection = self

        return items

    def unlink_flexible_gpu(
        self, flexible_gpu_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "UnlinkFlexibleGpu", FlexibleGpuId=flexible_gpu_id, **params
        )
        return

    def unlink_internet_service(
        self, internet_service_id: str, net_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "UnlinkInternetService",
            InternetServiceId=internet_service_id,
            NetId=net_id,
            **params
        )
        return

    def unlink_load_balancer_backend_machines(
        self,
        load_balancer_name: str,
        backend_ips: Optional[list[str]] = None,
        backend_vm_ids: Optional[list[str]] = None,
        dry_run: Optional[bool] = None,
    ) -> None:
        params = {}
        if backend_ips is not None:
            params["BackendIps"] = backend_ips
        if backend_vm_ids is not None:
            params["BackendVmIds"] = backend_vm_ids
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "UnlinkLoadBalancerBackendMachines",
            LoadBalancerName=load_balancer_name,
            **params
        )
        return

    def unlink_nic(self, link_nic_id: str, dry_run: Optional[bool] = None) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("UnlinkNic", LinkNicId=link_nic_id, **params)
        return

    def unlink_private_ips(
        self, nic_id: str, private_ips: list[str], dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "UnlinkPrivateIps", NicId=nic_id, PrivateIps=private_ips, **params
        )
        return

    def unlink_public_ip(
        self,
        dry_run: Optional[bool] = None,
        link_public_ip_id: Optional[str] = None,
        public_ip: Optional[str] = None,
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if link_public_ip_id is not None:
            params["LinkPublicIpId"] = link_public_ip_id
        if public_ip is not None:
            params["PublicIp"] = public_ip
        response = self.make_request("UnlinkPublicIp", **params)
        return

    def unlink_route_table(
        self, link_route_table_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "UnlinkRouteTable", LinkRouteTableId=link_route_table_id, **params
        )
        return

    def unlink_virtual_gateway(
        self, net_id: str, virtual_gateway_id: str, dry_run: Optional[bool] = None
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "UnlinkVirtualGateway",
            NetId=net_id,
            VirtualGatewayId=virtual_gateway_id,
            **params
        )
        return

    def unlink_volume(
        self,
        volume_id: str,
        dry_run: Optional[bool] = None,
        force_unlink: Optional[bool] = None,
    ) -> None:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if force_unlink is not None:
            params["ForceUnlink"] = force_unlink
        response = self.make_request("UnlinkVolume", VolumeId=volume_id, **params)
        return

    def update_access_key(
        self,
        access_key_id: str,
        state: str,
        dry_run: Optional[bool] = None,
        expiration_date: Optional[str] = None,
    ) -> AccessKey:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if expiration_date is not None:
            params["ExpirationDate"] = expiration_date
        response = self.make_request(
            "UpdateAccessKey", AccessKeyId=access_key_id, State=state, **params
        )

        item = deserialize(AccessKey, response["AccessKey"])

        item._connection = self

        return item

    def update_account(
        self,
        additional_emails: Optional[list[str]] = None,
        city: Optional[str] = None,
        company_name: Optional[str] = None,
        country: Optional[str] = None,
        dry_run: Optional[bool] = None,
        email: Optional[str] = None,
        first_name: Optional[str] = None,
        job_title: Optional[str] = None,
        last_name: Optional[str] = None,
        mobile_number: Optional[str] = None,
        phone_number: Optional[str] = None,
        state_province: Optional[str] = None,
        vat_number: Optional[str] = None,
        zip_code: Optional[str] = None,
    ) -> Account:
        params = {}
        if additional_emails is not None:
            params["AdditionalEmails"] = additional_emails
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
        response = self.make_request("UpdateAccount", **params)

        item = deserialize(Account, response["Account"])

        item._connection = self

        return item

    def update_api_access_policy(
        self,
        max_access_key_expiration_seconds: int,
        require_trusted_env: bool,
        dry_run: Optional[bool] = None,
    ) -> ApiAccessPolicy:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "UpdateApiAccessPolicy",
            MaxAccessKeyExpirationSeconds=max_access_key_expiration_seconds,
            RequireTrustedEnv=require_trusted_env,
            **params
        )

        item = deserialize(ApiAccessPolicy, response["ApiAccessPolicy"])

        item._connection = self

        return item

    def update_api_access_rule(
        self,
        api_access_rule_id: str,
        ca_ids: Optional[list[str]] = None,
        cns: Optional[list[str]] = None,
        description: Optional[str] = None,
        dry_run: Optional[bool] = None,
        ip_ranges: Optional[list[str]] = None,
    ) -> ApiAccessRule:
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
        response = self.make_request(
            "UpdateApiAccessRule", ApiAccessRuleId=api_access_rule_id, **params
        )

        item = deserialize(ApiAccessRule, response["ApiAccessRule"])

        item._connection = self

        return item

    def update_ca(
        self,
        ca_id: str,
        description: Optional[str] = None,
        dry_run: Optional[bool] = None,
    ) -> Ca:
        params = {}
        if description is not None:
            params["Description"] = description
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request("UpdateCa", CaId=ca_id, **params)

        item = deserialize(Ca, response["Ca"])

        item._connection = self

        return item

    def update_flexible_gpu(
        self,
        flexible_gpu_id: str,
        delete_on_vm_deletion: Optional[bool] = None,
        dry_run: Optional[bool] = None,
    ) -> FlexibleGpu:
        params = {}
        if delete_on_vm_deletion is not None:
            params["DeleteOnVmDeletion"] = delete_on_vm_deletion
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "UpdateFlexibleGpu", FlexibleGpuId=flexible_gpu_id, **params
        )

        item = deserialize(FlexibleGpu, response["FlexibleGpu"])

        item._connection = self

        return item

    def update_image(
        self,
        image_id: str,
        permissions_to_launch: "PermissionsOnResourceCreation",
        dry_run: Optional[bool] = None,
    ) -> Image:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "UpdateImage",
            ImageId=image_id,
            PermissionsToLaunch=serialize(permissions_to_launch),
            **params
        )

        item = deserialize(Image, response["Image"])

        item._connection = self

        return item

    def update_listener_rule(
        self,
        listener_rule_name: str,
        dry_run: Optional[bool] = None,
        host_pattern: Optional[str] = None,
        path_pattern: Optional[str] = None,
    ) -> ListenerRule:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if host_pattern is not None:
            params["HostPattern"] = host_pattern
        if path_pattern is not None:
            params["PathPattern"] = path_pattern
        response = self.make_request(
            "UpdateListenerRule", ListenerRuleName=listener_rule_name, **params
        )

        item = deserialize(ListenerRule, response["ListenerRule"])

        item._connection = self

        return item

    def update_load_balancer(
        self,
        load_balancer_name: str,
        access_log: Optional["AccessLog"] = None,
        dry_run: Optional[bool] = None,
        health_check: Optional["HealthCheck"] = None,
        load_balancer_port: Optional[int] = None,
        policy_names: Optional[list[str]] = None,
        public_ip: Optional[str] = None,
        security_groups: Optional[list[str]] = None,
        server_certificate_id: Optional[str] = None,
    ) -> LoadBalancer:
        params = {}
        if access_log is not None:
            params["AccessLog"] = serialize(access_log)
        if dry_run is not None:
            params["DryRun"] = dry_run
        if health_check is not None:
            params["HealthCheck"] = serialize(health_check)
        if load_balancer_port is not None:
            params["LoadBalancerPort"] = load_balancer_port
        if policy_names is not None:
            params["PolicyNames"] = policy_names
        if public_ip is not None:
            params["PublicIp"] = public_ip
        if security_groups is not None:
            params["SecurityGroups"] = security_groups
        if server_certificate_id is not None:
            params["ServerCertificateId"] = server_certificate_id
        response = self.make_request(
            "UpdateLoadBalancer", LoadBalancerName=load_balancer_name, **params
        )

        item = deserialize(LoadBalancer, response["LoadBalancer"])

        item._connection = self

        return item

    def update_net(
        self, dhcp_options_set_id: str, net_id: str, dry_run: Optional[bool] = None
    ) -> Net:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "UpdateNet", DhcpOptionsSetId=dhcp_options_set_id, NetId=net_id, **params
        )

        item = deserialize(Net, response["Net"])

        item._connection = self

        return item

    def update_net_access_point(
        self,
        net_access_point_id: str,
        add_route_table_ids: Optional[list[str]] = None,
        dry_run: Optional[bool] = None,
        remove_route_table_ids: Optional[list[str]] = None,
    ) -> NetAccessPoint:
        params = {}
        if add_route_table_ids is not None:
            params["AddRouteTableIds"] = add_route_table_ids
        if dry_run is not None:
            params["DryRun"] = dry_run
        if remove_route_table_ids is not None:
            params["RemoveRouteTableIds"] = remove_route_table_ids
        response = self.make_request(
            "UpdateNetAccessPoint", NetAccessPointId=net_access_point_id, **params
        )

        item = deserialize(NetAccessPoint, response["NetAccessPoint"])

        item._connection = self

        return item

    def update_nic(
        self,
        nic_id: str,
        description: Optional[str] = None,
        dry_run: Optional[bool] = None,
        link_nic: Optional["LinkNicToUpdate"] = None,
        security_group_ids: Optional[list[str]] = None,
    ) -> Nic:
        params = {}
        if description is not None:
            params["Description"] = description
        if dry_run is not None:
            params["DryRun"] = dry_run
        if link_nic is not None:
            params["LinkNic"] = serialize(link_nic)
        if security_group_ids is not None:
            params["SecurityGroupIds"] = security_group_ids
        response = self.make_request("UpdateNic", NicId=nic_id, **params)

        item = deserialize(Nic, response["Nic"])

        item._connection = self

        return item

    def update_route(
        self,
        destination_ip_range: str,
        route_table_id: str,
        dry_run: Optional[bool] = None,
        gateway_id: Optional[str] = None,
        nat_service_id: Optional[str] = None,
        net_peering_id: Optional[str] = None,
        nic_id: Optional[str] = None,
        vm_id: Optional[str] = None,
    ) -> RouteTable:
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
        response = self.make_request(
            "UpdateRoute",
            DestinationIpRange=destination_ip_range,
            RouteTableId=route_table_id,
            **params
        )

        item = deserialize(RouteTable, response["RouteTable"])

        item._connection = self

        return item

    def update_route_propagation(
        self,
        enable: bool,
        route_table_id: str,
        virtual_gateway_id: str,
        dry_run: Optional[bool] = None,
    ) -> RouteTable:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "UpdateRoutePropagation",
            Enable=enable,
            RouteTableId=route_table_id,
            VirtualGatewayId=virtual_gateway_id,
            **params
        )

        item = deserialize(RouteTable, response["RouteTable"])

        item._connection = self

        return item

    def update_server_certificate(
        self,
        name: str,
        dry_run: Optional[bool] = None,
        new_name: Optional[str] = None,
        new_path: Optional[str] = None,
    ) -> ServerCertificate:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if new_name is not None:
            params["NewName"] = new_name
        if new_path is not None:
            params["NewPath"] = new_path
        response = self.make_request("UpdateServerCertificate", Name=name, **params)

        item = deserialize(ServerCertificate, response["ServerCertificate"])

        item._connection = self

        return item

    def update_snapshot(
        self,
        permissions_to_create_volume: "PermissionsOnResourceCreation",
        snapshot_id: str,
        dry_run: Optional[bool] = None,
    ) -> Snapshot:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "UpdateSnapshot",
            PermissionsToCreateVolume=serialize(permissions_to_create_volume),
            SnapshotId=snapshot_id,
            **params
        )

        item = deserialize(Snapshot, response["Snapshot"])

        item._connection = self

        return item

    def update_subnet(
        self,
        map_public_ip_on_launch: bool,
        subnet_id: str,
        dry_run: Optional[bool] = None,
    ) -> Subnet:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        response = self.make_request(
            "UpdateSubnet",
            MapPublicIpOnLaunch=map_public_ip_on_launch,
            SubnetId=subnet_id,
            **params
        )

        item = deserialize(Subnet, response["Subnet"])

        item._connection = self

        return item

    def update_vm(
        self,
        vm_id: str,
        block_device_mappings: Optional[list["BlockDeviceMappingVmUpdate"]] = None,
        bsu_optimized: Optional[bool] = None,
        deletion_protection: Optional[bool] = None,
        dry_run: Optional[bool] = None,
        is_source_dest_checked: Optional[bool] = None,
        keypair_name: Optional[str] = None,
        performance: Optional[str] = None,
        security_group_ids: Optional[list[str]] = None,
        user_data: Optional[str] = None,
        vm_initiated_shutdown_behavior: Optional[str] = None,
        vm_type: Optional[str] = None,
    ) -> Vm:
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
        response = self.make_request("UpdateVm", VmId=vm_id, **params)

        item = deserialize(Vm, response["Vm"])

        item._connection = self

        return item

    def update_volume(
        self,
        volume_id: str,
        dry_run: Optional[bool] = None,
        iops: Optional[int] = None,
        size: Optional[int] = None,
        volume_type: Optional[str] = None,
    ) -> Volume:
        params = {}
        if dry_run is not None:
            params["DryRun"] = dry_run
        if iops is not None:
            params["Iops"] = iops
        if size is not None:
            params["Size"] = size
        if volume_type is not None:
            params["VolumeType"] = volume_type
        response = self.make_request("UpdateVolume", VolumeId=volume_id, **params)

        item = deserialize(Volume, response["Volume"])

        item._connection = self

        return item

    def update_vpn_connection(
        self,
        vpn_connection_id: str,
        client_gateway_id: Optional[str] = None,
        dry_run: Optional[bool] = None,
        virtual_gateway_id: Optional[str] = None,
        vpn_options: Optional["VpnOptions"] = None,
    ) -> VpnConnection:
        params = {}
        if client_gateway_id is not None:
            params["ClientGatewayId"] = client_gateway_id
        if dry_run is not None:
            params["DryRun"] = dry_run
        if virtual_gateway_id is not None:
            params["VirtualGatewayId"] = virtual_gateway_id
        if vpn_options is not None:
            params["VpnOptions"] = serialize(vpn_options)
        response = self.make_request(
            "UpdateVpnConnection", VpnConnectionId=vpn_connection_id, **params
        )

        item = deserialize(VpnConnection, response["VpnConnection"])

        item._connection = self

        return item
