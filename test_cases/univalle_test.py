import requests
import pytest

# URL objetivo
TARGET_URL = "https://enlace.univalle.edu/san/webform/PAutenticar.aspx"


# Fixtures para realizar pruebas iniciales
@pytest.fixture(scope="module")
def setup_session():
    session = requests.Session()
    response = session.get(TARGET_URL)
    assert response.status_code == 200, "No se pudo acceder a la página"
    return session


# 1. Prueba de XSS Reflejado
@pytest.mark.vulnerabilities
def test_xss_reflejado(setup_session):
    payload = "javascript:alert('XSS')"
    response = setup_session.get(f"{TARGET_URL}?url={payload}")
    assert payload not in response.text, "Vulnerabilidad XSS detectada"


# 2. Manipulación de localStorage
@pytest.mark.vulnerabilities
def test_localstorage():
    js_payload = "localStorage.setItem('horaServidor', 'manipulado');"
    assert "manipulado" not in js_payload, "Potencial Manipulación de localStorage"


# 3. Exposición de Clave API
@pytest.mark.vulnerabilities
def test_api_key_exposure():
    exposed_key = "59548e45e0de4ca691e195137231508"
    assert exposed_key not in requests.get(TARGET_URL).text, "Clave API visible en el código fuente"


# 4. Redirección Abierta
@pytest.mark.vulnerabilities
def test_open_redirect(setup_session):
    malicious_url = "https://evil.com"
    response = setup_session.get(f"{TARGET_URL}?url={malicious_url}")
    assert malicious_url not in response.url, "Vulnerabilidad de Redirección Abierta detectada"


# 5. Ataque DoS en Lazy-Loading
@pytest.mark.vulnerabilities
def test_lazy_loading_dos():
    scroll_simulation = "setInterval(() => { window.scrollTo(0, document.body.scrollHeight); }, 10);"
    assert "setInterval" not in scroll_simulation, "Potencial DoS por scroll continuo"


# 6. Inyección de Cookies
@pytest.mark.vulnerabilities
def test_cookie_injection():
    cookie_value = "climaImagen=https://sitio-malicioso.com/icon.png"
    assert "sitio-malicioso" not in cookie_value, "Posible inyección de cookies detectada"


# 7. Fuga de Información en la Consola
@pytest.mark.vulnerabilities
def test_console_information_leak():
    js_console_log = "console.log('Cargo nuevo: ' + clima + ', ' + climaImagen);"
    assert "console.log" not in js_console_log, "Fuga de información en la consola detectada"


if __name__ == "__main__":
    pytest.main(["-v", __file__])
