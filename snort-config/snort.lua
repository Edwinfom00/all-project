-- Configuration de base pour Snort 3
-- À adapter selon vos besoins

HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- Variables pour les ports
HTTP_PORTS = '80,8080'
SQL_PORTS = '1433,3306,5432'
SSH_PORTS = '22'

-- Configuration des inspecteurs
ips = {
    -- Activation des règles locales
    enable_builtin_rules = true,
    rules = [[
        include $RULE_PATH/local.rules
    ]],
    variables = {
        nets = {
            HOME_NET = HOME_NET,
            EXTERNAL_NET = EXTERNAL_NET
        },
        ports = {
            HTTP_PORTS = HTTP_PORTS,
            SQL_PORTS = SQL_PORTS,
            SSH_PORTS = SSH_PORTS
        }
    }
}

-- Configuration du logging
alert_csv = {
    file = true,
    fields = 'timestamp,msg,src_addr,src_port,dst_addr,dst_port,proto,classification'
}

-- Configuration des décodeurs réseau
wizard = default_wizard

normalizer = {
    tcp = {
        ips = true,
        trim = true
    }
}

-- Configuration des inspecteurs de protocoles
http_inspect = {
    response_depth = 0,
    request_depth = 0
}

port_scan = {
    protos = 'all',
    scan_type = 'all',
    memcap = 10000000
} 