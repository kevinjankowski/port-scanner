import socket
import time


def tcp_full_handshake_scan(target_host, ports):
    """
    Skanuje porty docelowego hosta metodą pełnego handshake TCP.

    Args:
        target_host (str): Adres IP lub nazwa domeny hosta docelowego
        ports (list): Lista portów do skanowania

    Returns:
        dict: Słownik z wynikami skanowania w formacie {port: status}
    """
    open_ports = {}

    # Rozwiązanie nazwy domeny na adres IP, jeśli to konieczne
    try:
        ip = socket.gethostbyname(target_host)
        print(f"Skanowanie hosta: {target_host} ({ip})")
    except socket.gaierror:
        print(f"Nie można rozwiązać nazwy hosta: {target_host}")
        return open_ports

    # Skanowanie każdego portu
    for port in ports:
        try:
            # Utworzenie socketu TCP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)  # Timeout 1 sekunda

            # Próba nawiązania połączenia (pełny handshake TCP)
            start_time = time.time()
            result = s.connect_ex((ip, port))
            end_time = time.time()

            response_time = round((end_time - start_time) * 1000, 2)  # Czas odpowiedzi w ms

            # Interpretacja wyniku
            if result == 0:
                print(f"Port {port}: Otwarty (czas odpowiedzi: {response_time} ms)")
                open_ports[port] = "Otwarty"
            else:
                print(f"Port {port}: Zamknięty lub filtrowany")
                open_ports[port] = "Zamknięty lub filtrowany"

            # Zamknięcie socketu
            s.close()

        except socket.timeout:
            print(f"Port {port}: Filtrowany (timeout)")
            open_ports[port] = "Filtrowany (timeout)"
        except socket.error as e:
            print(f"Port {port}: Błąd - {e}")
            open_ports[port] = f"Błąd - {e}"

    return open_ports

