# Network Security Monitoring Assessment

## 1. Project Overview

The Python Network Security Monitoring Tool is a defensive analysis project designed to examine network-flow records and identify potentially unusual activity.

## 2. Objective

The objective is to demonstrate basic network monitoring, traffic analysis, and security alert reporting using Python.

## 3. Tools and Technologies

- Kali Linux
- Python 3
- CSV data processing
- Python Counter collections

## 4. Testing Methodology

The tool was tested using a simulated network traffic dataset.

The analysis checks:
- Total recorded connections.
- Traffic volume by source IP address.
- Blocked connection attempts.
- Repeated blocked connections.
- Individual connections exceeding 50,000 bytes.

## 5. Security Findings

The sample dataset is designed to demonstrate two alert types:

| Finding | Detection condition |
|---|---|
| High traffic | A connection transfers more than 50,000 bytes |
| Repeated blocked connections | A source IP has at least 3 blocked connections |

## 6. Security Recommendations

1. Investigate unusual traffic volumes using authorised network monitoring systems.
2. Review repeated blocked connections.
3. Apply appropriate firewall rules.
4. Maintain accurate network logs.
5. Investigate alerts before classifying activity as malicious.

## 7. Limitations

- The project analyses CSV records, not live network traffic.
- Detection thresholds are basic examples.
- Alerts do not prove that an attack has occurred.
- The tool does not block traffic or modify firewall settings.
- The sample data is simulated.

## 8. Conclusion

This project demonstrates how Python can support basic defensive network monitoring and traffic analysis. It provides a foundation for learning network security monitoring and developing more advanced defensive analysis tools.

## 9. Testing Disclaimer

All network records used in this demonstration are simulated. No third-party network was monitored or accessed.
