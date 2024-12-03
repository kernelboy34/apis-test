import pytest
from zapv2 import ZAPv2

ZAP_API_KEY = 'TU_ZAP_API_KEY'  # Sustituye con tu clave de API de OWASP ZAP si es necesaria
ZAP_ADDRESS = 'http://localhost'
ZAP_PORT = '8080'
ZAP_TARGET = 'https://ratio-software-bo.tech'  

zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': f'{ZAP_ADDRESS}:{ZAP_PORT}', 'https': f'{ZAP_ADDRESS}:{ZAP_PORT}'})

@pytest.fixture(scope='module', autouse=True)
def zap_setup():
    print(f"Iniciando escaneo en {ZAP_TARGET}")
    zap.urlopen(ZAP_TARGET)
    zap.spider.scan(ZAP_TARGET)
    while int(zap.spider.status()) < 100:
        pass
    zap.ascan.scan(ZAP_TARGET)
    while int(zap.ascan.status()) < 100:
        pass

    yield
    print("Escaneo finalizado.")

@pytest.mark.zap_scan
def test_zap_report():
    alerts = zap.core.alerts(baseurl=ZAP_TARGET)
    report = generate_report(alerts)
    print(report)
    assert all(alert['risk'] != 'High' for alert in alerts), "¡Se encontraron alertas de riesgo alto!"

def generate_report(alerts):
    risk_levels = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    specific_alerts = {}
    
    for alert in alerts:
        risk_levels[alert['risk']] += 1
        name = alert['alert']
        instances = alert['instances']
        specific_alerts[name] = specific_alerts.get(name, {"risk": alert['risk'], "instances": 0})
        specific_alerts[name]['instances'] += len(instances)

    report = (
        f"\nZAP Scanning Report\n"
        f"--------------------\n"
        f"Risk Level\tNumber of Alerts\n"
        f"High\t\t{risk_levels['High']}\n"
        f"Medium\t\t{risk_levels['Medium']}\n"
        f"Low\t\t{risk_levels['Low']}\n"
        f"Informational\t{risk_levels['Informational']}\n\n"
        f"Name\tRisk Level\tNumber of Instances\n"
    )

    for alert, details in specific_alerts.items():
        report += f"{alert}\t{details['risk']}\t{details['instances']}\n"
    
    return report

if __name__ == "__main__":
    pytest.main(["-v", __file__])
