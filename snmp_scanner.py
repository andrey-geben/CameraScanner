#опрос SNMP (v1/v2c/v3) GET-запросы к стандартным OID MIB-II и вендорским OID Hikvision
# snmp_scanner.py
import asyncio
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    CommunityData,
    UsmUserData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
    usmHMACSHAAuthProtocol,
    usmAesCfb128Protocol,
)

MIB2_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
}

HIKVISION_OIDS = {
    "hik_deviceID": "1.3.6.1.4.1.39165.1.1.0",
    "hik_nvr_oid": "1.3.6.1.4.1.50001.1.240.0",
}


async def snmp_get_async(ip: str, version: str, community: str = "public", v3_params: dict | None = None) -> dict:
    """
    Асинхронный SNMP GET для стандартных и вендорских OID.
    version: 'v1', 'v2c' или 'v3'.
    """
    results: dict = {}
    all_oids = {**MIB2_OIDS, **HIKVISION_OIDS}

    if version == "v1":
        auth_data = CommunityData(community, mpModel=0)
    elif version == "v2c":
        auth_data = CommunityData(community, mpModel=1)
    elif version == "v3":
        if not v3_params:
            return {"error": "SNMPv3 parameters required"}
        auth_data = UsmUserData(
            v3_params["user"],
            v3_params.get("auth_key"),
            v3_params.get("priv_key"),
            authProtocol=v3_params.get("auth_proto", usmHMACSHAAuthProtocol),
            privProtocol=v3_params.get("priv_proto", usmAesCfb128Protocol),
        )
    else:
        return {"error": f"Unsupported SNMP version: {version}"}

    snmp_engine = SnmpEngine()
    transport = await UdpTransportTarget.create((ip, 161), timeout=1, retries=0)

    for name, oid in all_oids.items():
        try:
            error_indication, error_status, _, var_binds = await get_cmd(
                snmp_engine,
                auth_data,
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
            if error_indication:
                results[name] = f"Error: {error_indication}"
            elif error_status:
                results[name] = f"Error: {error_status.prettyPrint()}"
            else:
                for var_bind in var_binds:
                    results[name] = var_bind[1].prettyPrint()
        except Exception as exc:
            results[name] = f"Exception: {exc}"

    return results


def snmp_get(ip: str, version: str, community: str = "public", v3_params: dict | None = None) -> dict:
    """
    Синхронная обёртка для вызова из потока GUI.
    """
    return asyncio.run(snmp_get_async(ip, version, community, v3_params))