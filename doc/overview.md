
# CanDIG Token Tracer Program

---

## Overview

* Python command line program deployable on Keycloak authentication servers

* Listens through the ethernet interface of the Keycloak software containers for container deployment

* Uses pyshark library frontend for tshark for packet sniffing capabilites

* Continuously searches for HTTP requests to the token endpoint of the Keycloak server and the resulting Keycloak server response

* Extracts the Access Token, Refresh Token, and Id Token provided from these requests and prints header and payload data to stdout

* Captures both first-time authentication requests using a one-time access code provided by Keycloak after login and refresh token requests 

* Refresh token requests are used when the access token has expired to retrieve a new set of tokens

* Authorization code requests are used when the user has no valid tokens and must authenticate via a username and password to retrieve a set of tokens

* The program may output a json-formatted file containing the information extracted from each request and response

* The program also tracks:

** Expiry times of access and refresh tokens
** Source and destination IP and port numbers
** Client secret 
** Client Id

* Command line arguments are planned to be added

---

## Examples:

---

### Example 1 - Refresh Token Request:

A user attempts to access the GA4GH server with an expired access token and unexpired refresh token. A request is made to the token endpoint of the Keycloak server to retrieve a new set of tokens using the unexpired refresh token.

./tokenTracer.py

HTTP Protocol:        POST /auth/realms/CanDIG/protocol/openid-connect/token HTTP/1.1\r\n
Packet Size:          1481
Source:               172.17.0.1:56648
Destination:          172.17.0.2:8080
Client Secret:        250e42b8-3f41-4d0f-9b6b-e32e09fccaf7
Client Id:            ga4ghServer
Grant Type:           refresh_token
Refresh Token:        eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJoWldPSWExUWJXczNWZjVDX2NpWTRsU1U0ZjRacHZWLXdKRHZHVkMtWXNnIn0.eyJqdGkiOiI3NDY0YTdjOC01NzQzLTRlNDYtOTEyMC01MzVkMTU5ZGQ3MjAiLCJleHAiOjE1MDg3NzU0NjQsIm5iZiI6MCwiaWF0IjoxNTA4NzczNjY0LCJpc3MiOiJodHRwOi8vMTkyLjE2OC45OS4xMDA6ODA4MC9hdXRoL3JlYWxtcy9DYW5ESUciLCJhdWQiOiJnYTRnaFNlcnZlciIsInN1YiI6IjhhMzViYWI0LWMxZTktNDUzNi1iOWEwLTViZjI5MDA0Y2RlYyIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJnYTRnaFNlcnZlciIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6IjFkMDA5NWE3LTg0MDEtNDYwYi1hMjAxLTEzMGM5MjdlODM0YiIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX19.Qeba3s9E_zjROppZxT5FL2Je0iQ7W4wpIPKW7I_TyImzdyxkHWxLjYxQFoSr1xA5rRa7QWVRwDfjli5xrFq5U1NLlvOBWkAaVrIMsiOAh8a5URLR1WnfTtcQF6-qyez64f-Sx5JY4U8oLhf0UsZAOo8yMMWYozkuB_7Lfv_D6GzGZatKqk-oWbWPdvjX5k-J-7x2T8dkwn7d07ZfAO8OghaxhD_zN0rEQuruwBx5Wl6vJpF5DqNvDX7TYUBturJb5-jKhN8juiP_HFCr6QET9k3DSLtxyD_wpmDOPp4_OY3-R6gYtFFRfzzdnBp8dm6Azj_q5oVldR_wX7Tncb3xAw

HTTP Protocol:        HTTP/1.1 200 OK\r\n
Packet Size:          3582
Source:               172.17.0.2:8080
Destination:          172.17.0.1:56648
Access Token:         eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJoWldPSWExUWJXczNWZjVDX2NpWTRsU1U0ZjRacHZWLXdKRHZHVkMtWXNnIn0.eyJqdGkiOiJiNjBhMDZmMS1mMWNhLTRiNzctODhjZi1mYTAyYWRmZGVkNGUiLCJleHAiOjE1MDg3NzQwMjQsIm5iZiI6MCwiaWF0IjoxNTA4NzczOTY0LCJpc3MiOiJodHRwOi8vMTkyLjE2OC45OS4xMDA6ODA4MC9hdXRoL3JlYWxtcy9DYW5ESUciLCJhdWQiOiJnYTRnaFNlcnZlciIsInN1YiI6IjhhMzViYWI0LWMxZTktNDUzNi1iOWEwLTViZjI5MDA0Y2RlYyIsInR5cCI6IkJlYXJlciIsImF6cCI6ImdhNGdoU2VydmVyIiwiYXV0aF90aW1lIjoxNTA4NzczNjY0LCJzZXNzaW9uX3N0YXRlIjoiMWQwMDk1YTctODQwMS00NjBiLWEyMDEtMTMwYzkyN2U4MzRiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6W10sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInByZWZlcnJlZF91c2VybmFtZSI6InVzZXIifQ.mMRQQsur1W9Nef-67gZKc71lB3laRuLb16uC7S-E7OqcypJs9cDwFLx1LVub_qL6WiyqczF9HMEhktq1rDaUWlwM-nXdPOjAQRB_C2pGDxX4Jl7iLoVf7x3OJKqoW6BWyDatXftl6oDg9k3TO0kjNot-2BD_VeW8703WXxF8tT4ZqeF3lwTlbrIF2Y1GDquS4O7pgoaugNJGcxIvH1GrJS_gJKcTlAut_9qkBw0V7IBdJagClp7jA1tq_NTcPqc4Dj8xwTVWKsQ_KShUZVtnE5ObAM8uHJ3I1mOriOvI6QsJY8__iM9Cn0Eh0PzT4aJfbWWtekUnHX0916g5rV_N9Q
Access Token Expiry:  60
Refresh Token:        eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJoWldPSWExUWJXczNWZjVDX2NpWTRsU1U0ZjRacHZWLXdKRHZHVkMtWXNnIn0.eyJqdGkiOiJlYTUyMWI3My0xODA2LTRmYjUtOWUzYS1jZDA2OTdhZDQxMmQiLCJleHAiOjE1MDg3NzU3NjQsIm5iZiI6MCwiaWF0IjoxNTA4NzczOTY0LCJpc3MiOiJodHRwOi8vMTkyLjE2OC45OS4xMDA6ODA4MC9hdXRoL3JlYWxtcy9DYW5ESUciLCJhdWQiOiJnYTRnaFNlcnZlciIsInN1YiI6IjhhMzViYWI0LWMxZTktNDUzNi1iOWEwLTViZjI5MDA0Y2RlYyIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJnYTRnaFNlcnZlciIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6IjFkMDA5NWE3LTg0MDEtNDYwYi1hMjAxLTEzMGM5MjdlODM0YiIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX19.KGtnJab-3T31DX-QlifvSBARVVsNjZ6nyFMBpOd4soiXx-CV93zQa8eXKOfwHoHED4jFctilefROVfWU2kVlw_NpAhHsj0LTpLgTHPWUEa7GGc6V3iU1_yQaJwE7YMiDegcGp7L1aA7gISb8AGy3CvAwyveTPZiUZq4OOf47xtA6E_tw1Q_lKtu5QOmiAf8Lpbifk1R2ZhY5YuYOPTPQG4QfBA9P5yoIQ_-DptrKhj8emq_0nMrRupvXkHr3ySI0dF3y0wIObfK6z0uh26qdrDwuLURscaTnmSdoqycd1XiUUm4z2SI86sIqBsE2rUoIkK113oNoTdcvMmC-SZCjfQ
Refresh Token Expiry: 1800
Token Type:           bearer
Id Token:             eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJoWldPSWExUWJXczNWZjVDX2NpWTRsU1U0ZjRacHZWLXdKRHZHVkMtWXNnIn0.eyJqdGkiOiJjNDcwMTlmZS0zZjNiLTQ0Y2QtYjczYy0wOWI3MjMyNzM2YWQiLCJleHAiOjE1MDg3NzQwMjQsIm5iZiI6MCwiaWF0IjoxNTA4NzczOTY0LCJpc3MiOiJodHRwOi8vMTkyLjE2OC45OS4xMDA6ODA4MC9hdXRoL3JlYWxtcy9DYW5ESUciLCJhdWQiOiJnYTRnaFNlcnZlciIsInN1YiI6IjhhMzViYWI0LWMxZTktNDUzNi1iOWEwLTViZjI5MDA0Y2RlYyIsInR5cCI6IklEIiwiYXpwIjoiZ2E0Z2hTZXJ2ZXIiLCJhdXRoX3RpbWUiOjE1MDg3NzM2NjQsInNlc3Npb25fc3RhdGUiOiIxZDAwOTVhNy04NDAxLTQ2MGItYTIwMS0xMzBjOTI3ZTgzNGIiLCJhY3IiOiIxIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlciJ9.XtXEoUBvHZ5zrJqWDzbiyHMMA1ERvK3pw77AXnGUKy-m4yv7j_Qm0dTMEd-kovVPhvkSDDHIu-35QUl_8fdQpQHldQ97bKJDjAaZjAN8YyzObIYh0SMrJw-jAT8S_m-COzqpWb38H1iGlwa3jgdBz08maOI6KNepSVIbqfp2-sdxsHc1zgMCVnhBlcEcO144eerR0Hn20vTTrHaNy7bBSZncxGYhWxeFPT15yI34I7XHYe2_zHfas8KmBfZVkAuNhPK84CFC-Ixm0hnJDLK5hhh71_Ofg3ayitd2DlNqrX2vwbC59SBgy_4Q7P5dYzNFz4cBgHIUnMYfLlaHXX5EGg

See also example1.png for the corresponding screen capture of the command line.

---

### Example 2 - Access Code Login 

A user attempts to access the GA4GH server with no tokens or all expired tokens. A request is made for a set of tokens using a one-time access code provided after authenticating through the redirected Keycloak login page.

./tokenTracer.py

HTTP Protocol:        POST /auth/realms/CanDIG/protocol/openid-connect/token HTTP/1.1\r\n
Packet Size:          617
Source:               172.17.0.1:56644
Destination:          172.17.0.2:8080
Client Secret:        250e42b8-3f41-4d0f-9b6b-e32e09fccaf7
Client Id:            ga4ghServer
Grant Type:           authorization_code
Authorization Code:   uss.aanh_9Uqg0xWV6WLBioNx3Pq3h5nocT_gbWVInxuU6s.9a3cbd3f-e689-452e-938a-9e9492018d97.0ef863dc-9f6d-4b7e-a706-4e460b4ba2e4
Redirect Uri:         http://192.168.99.100:8000/oidc_callback
Scope:                openid email

HTTP Protocol:        HTTP/1.1 200 OK\r\n
Packet Size:          3582
Source:               172.17.0.2:8080
Destination:          172.17.0.1:56644
Access Token:         eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJoWldPSWExUWJXczNWZjVDX2NpWTRsU1U0ZjRacHZWLXdKRHZHVkMtWXNnIn0.eyJqdGkiOiJkNTgwNmZhNS03NWY4LTRiN2MtYmUwMC1lYzM3NWQ3ZDI1YTkiLCJleHAiOjE1MDg3NzM5MTQsIm5iZiI6MCwiaWF0IjoxNTA4NzczODU0LCJpc3MiOiJodHRwOi8vMTkyLjE2OC45OS4xMDA6ODA4MC9hdXRoL3JlYWxtcy9DYW5ESUciLCJhdWQiOiJnYTRnaFNlcnZlciIsInN1YiI6IjhhMzViYWI0LWMxZTktNDUzNi1iOWEwLTViZjI5MDA0Y2RlYyIsInR5cCI6IkJlYXJlciIsImF6cCI6ImdhNGdoU2VydmVyIiwiYXV0aF90aW1lIjoxNTA4NzczODU0LCJzZXNzaW9uX3N0YXRlIjoiOWEzY2JkM2YtZTY4OS00NTJlLTkzOGEtOWU5NDkyMDE4ZDk3IiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6W10sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInByZWZlcnJlZF91c2VybmFtZSI6InVzZXIifQ.Rq9KM9Y7X4v4msbyqUHAGvWPWu_HdpWpYPwWsjfevvUKcMr_XWJu-pmdWR0EuJk0xN-df5Mr4hfmhxwsGYNmSHMrZfgWn6I4oiyy0fKJOtrCKYZHiFDwaAa9yCvEFIqgkoAyyKpMUpR4bLM5d6m68LiduHoFbIec24Oedyy9Hb5Hfvr4FboY7c5lc_VYwDfkfEgo_ws0do10n93_3DJuxgCUB8f_zjyybUaCmmQZcINChFnXoyRKP2kMbuMOVryC4NyYAIZs0WKX3-9ZUe6zJiYTw0xq1JIn8ttz7b6AlckQtruM07t9qCmtjbzkg_olTGFJP4FFf7AzFRzpaSTtEQ
Access Token Expiry:  60
Refresh Token:        eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJoWldPSWExUWJXczNWZjVDX2NpWTRsU1U0ZjRacHZWLXdKRHZHVkMtWXNnIn0.eyJqdGkiOiIxZDBlMzMyZi1lOGQ3LTRhNjktOWQxZS03OWIzOGNmYjJlNjkiLCJleHAiOjE1MDg3NzU2NTQsIm5iZiI6MCwiaWF0IjoxNTA4NzczODU0LCJpc3MiOiJodHRwOi8vMTkyLjE2OC45OS4xMDA6ODA4MC9hdXRoL3JlYWxtcy9DYW5ESUciLCJhdWQiOiJnYTRnaFNlcnZlciIsInN1YiI6IjhhMzViYWI0LWMxZTktNDUzNi1iOWEwLTViZjI5MDA0Y2RlYyIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJnYTRnaFNlcnZlciIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6IjlhM2NiZDNmLWU2ODktNDUyZS05MzhhLTllOTQ5MjAxOGQ5NyIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX19.Eta9y41VKyferszRdWMSGtcS2vLDDFQYICoTYCNH_sEz_KEKiUu4ieufkHkPN00l9MY6hUTcUjlwFX7u1Yrf9V1cRZI5mTIezhygDRrcmiIem19KzH9S5rUCcfnvInaIAsdSUWXzMxT46J4MJ1jAtvTX18-fZo0NWl2E7rurCY0wLE7BI7jLSh8TmACvOofmXkbOxlaly67bc8sVr7s5Avx6IrTGhgJ2p5qYTSXMdMFaArlrdOrQr3-AjLi4snq4sGsOQuBxRI1oCbEaWz9bvvuGi7H2hC0xRFN3qMEga4X5twFUJXBb7paFX-38t6AYHwV_b3UvpQoyn51WdgFtYw
Refresh Token Expiry: 1800
Token Type:           bearer
Id Token:             eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJoWldPSWExUWJXczNWZjVDX2NpWTRsU1U0ZjRacHZWLXdKRHZHVkMtWXNnIn0.eyJqdGkiOiIyMTNiZmI2NS1lOWU2LTRlYjUtOTA5OS1kZGY3MjE2Y2JlNGEiLCJleHAiOjE1MDg3NzM5MTQsIm5iZiI6MCwiaWF0IjoxNTA4NzczODU0LCJpc3MiOiJodHRwOi8vMTkyLjE2OC45OS4xMDA6ODA4MC9hdXRoL3JlYWxtcy9DYW5ESUciLCJhdWQiOiJnYTRnaFNlcnZlciIsInN1YiI6IjhhMzViYWI0LWMxZTktNDUzNi1iOWEwLTViZjI5MDA0Y2RlYyIsInR5cCI6IklEIiwiYXpwIjoiZ2E0Z2hTZXJ2ZXIiLCJhdXRoX3RpbWUiOjE1MDg3NzM4NTQsInNlc3Npb25fc3RhdGUiOiI5YTNjYmQzZi1lNjg5LTQ1MmUtOTM4YS05ZTk0OTIwMThkOTciLCJhY3IiOiIxIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlciJ9.Cp_hTXEU9JQUuGJPGX_BK3f6JsowPIhxbyhmMrHEU7eKmUDkFloPgkoZqASot5NA_ze01_poV-U52j48dGDZy2HEt20lAyMfPo20WkcPHDI1-8FxktyP2HDSpUKaXGBnqidR8TM8Q8OfKu2XKp02p5-Wv9biM1nEPaUZH_8NoggiILItQ-Kz8nm6JoiGKOjLOKkisjJhl22FZ3KyfZAKSHx0Q9YYPjoWxHqLHsZYFq46yzgi-OHlYmAld3KK5UwrjfTgtv1rcgh51i029Vh5_syFEjvG1DfusDBUbuC8D0NtDqi7ipkwpAINwIzP1hbqdOdGWO8IA16TXN4LCuvMbg


See also example2.png for the corresponding screen capture of the command line.

---

### Example 3 - JSON Output File

The following JSON file contains the request/repsonse pairs of each of previous examples in their respective order. Each packet is formatted in its own JSON object on its own line. The data contained is identical to the data printed on stdout, but in a more easily parsed format.

tokenPacket.json

{"clientSecret": "250e42b8-3f41-4d0f-9b6b-e32e09fccaf7", "authorizationCode": "uss.aanh_9Uqg0xWV6WLBioNx3Pq3h5nocT_gbWVInxuU6s.9a3cbd3f-e689-452e-938a-9e9492018d97.0ef863dc-9f6d-4b7e-a706-4e460b4ba2e4", "packetSize": "617", "clientId": "ga4ghServer", "destIP": "172.17.0.2", "sourceIP": "172.17.0.1", "rediectUri": "http://192.168.99.100:8000/oidc_callback", "sourcePort": "56644", "scope": "openid email", "grantType": "authorization_code", "HTTP Header": "POST /auth/realms/CanDIG/protocol/openid-connect/token HTTP/1.1\\r\\n", "destPort": "8080"}
{"refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJoWldPSWExUWJXczNWZjVDX2NpWTRsU1U0ZjRacHZWLXdKRHZHVkMtWXNnIn0.eyJqdGkiOiIxZDBlMzMyZi1lOGQ3LTRhNjktOWQxZS03OWIzOGNmYjJlNjkiLCJleHAiOjE1MDg3NzU2NTQsIm5iZiI6MCwiaWF0IjoxNTA4NzczODU0LCJpc3MiOiJodHRwOi8vMTkyLjE2OC45OS4xMDA6ODA4MC9hdXRoL3JlYWxtcy9DYW5ESUciLCJhdWQiOiJnYTRnaFNlcnZlciIsInN1YiI6IjhhMzViYWI0LWMxZTktNDUzNi1iOWEwLTViZjI5MDA0Y2RlYyIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJnYTRnaFNlcnZlciIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6IjlhM2NiZDNmLWU2ODktNDUyZS05MzhhLTllOTQ5MjAxOGQ5NyIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX19.Eta9y41VKyferszRdWMSGtcS2vLDDFQYICoTYCNH_sEz_KEKiUu4ieufkHkPN00l9MY6hUTcUjlwFX7u1Yrf9V1cRZI5mTIezhygDRrcmiIem19KzH9S5rUCcfnvInaIAsdSUWXzMxT46J4MJ1jAtvTX18-fZo0NWl2E7rurCY0wLE7BI7jLSh8TmACvOofmXkbOxlaly67bc8sVr7s5Avx6IrTGhgJ2p5qYTSXMdMFaArlrdOrQr3-AjLi4snq4sGsOQuBxRI1oCbEaWz9bvvuGi7H2hC0xRFN3qMEga4X5twFUJXBb7paFX-38t6AYHwV_b3UvpQoyn51WdgFtYw", "tokenType": "bearer", "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJoWldPSWExUWJXczNWZjVDX2NpWTRsU1U0ZjRacHZWLXdKRHZHVkMtWXNnIn0.eyJqdGkiOiJkNTgwNmZhNS03NWY4LTRiN2MtYmUwMC1lYzM3NWQ3ZDI1YTkiLCJleHAiOjE1MDg3NzM5MTQsIm5iZiI6MCwiaWF0IjoxNTA4NzczODU0LCJpc3MiOiJodHRwOi8vMTkyLjE2OC45OS4xMDA6ODA4MC9hdXRoL3JlYWxtcy9DYW5ESUciLCJhdWQiOiJnYTRnaFNlcnZlciIsInN1YiI6IjhhMzViYWI0LWMxZTktNDUzNi1iOWEwLTViZjI5MDA0Y2RlYyIsInR5cCI6IkJlYXJlciIsImF6cCI6ImdhNGdoU2VydmVyIiwiYXV0aF90aW1lIjoxNTA4NzczODU0LCJzZXNzaW9uX3N0YXRlIjoiOWEzY2JkM2YtZTY4OS00NTJlLTkzOGEtOWU5NDkyMDE4ZDk3IiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6W10sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInByZWZlcnJlZF91c2VybmFtZSI6InVzZXIifQ.Rq9KM9Y7X4v4msbyqUHAGvWPWu_HdpWpYPwWsjfevvUKcMr_XWJu-pmdWR0EuJk0xN-df5Mr4hfmhxwsGYNmSHMrZfgWn6I4oiyy0fKJOtrCKYZHiFDwaAa9yCvEFIqgkoAyyKpMUpR4bLM5d6m68LiduHoFbIec24Oedyy9Hb5Hfvr4FboY7c5lc_VYwDfkfEgo_ws0do10n93_3DJuxgCUB8f_zjyybUaCmmQZcINChFnXoyRKP2kMbuMOVryC4NyYAIZs0WKX3-9ZUe6zJiYTw0xq1JIn8ttz7b6AlckQtruM07t9qCmtjbzkg_olTGFJP4FFf7AzFRzpaSTtEQ", "packetSize": "3582", "accessTokenExpiry": "60", "destIP": "172.17.0.1", "refreshTokenExpiry": "1800", "sourceIP": "172.17.0.2", "idToken": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJoWldPSWExUWJXczNWZjVDX2NpWTRsU1U0ZjRacHZWLXdKRHZHVkMtWXNnIn0.eyJqdGkiOiIyMTNiZmI2NS1lOWU2LTRlYjUtOTA5OS1kZGY3MjE2Y2JlNGEiLCJleHAiOjE1MDg3NzM5MTQsIm5iZiI6MCwiaWF0IjoxNTA4NzczODU0LCJpc3MiOiJodHRwOi8vMTkyLjE2OC45OS4xMDA6ODA4MC9hdXRoL3JlYWxtcy9DYW5ESUciLCJhdWQiOiJnYTRnaFNlcnZlciIsInN1YiI6IjhhMzViYWI0LWMxZTktNDUzNi1iOWEwLTViZjI5MDA0Y2RlYyIsInR5cCI6IklEIiwiYXpwIjoiZ2E0Z2hTZXJ2ZXIiLCJhdXRoX3RpbWUiOjE1MDg3NzM4NTQsInNlc3Npb25fc3RhdGUiOiI5YTNjYmQzZi1lNjg5LTQ1MmUtOTM4YS05ZTk0OTIwMThkOTciLCJhY3IiOiIxIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlciJ9.Cp_hTXEU9JQUuGJPGX_BK3f6JsowPIhxbyhmMrHEU7eKmUDkFloPgkoZqASot5NA_ze01_poV-U52j48dGDZy2HEt20lAyMfPo20WkcPHDI1-8FxktyP2HDSpUKaXGBnqidR8TM8Q8OfKu2XKp02p5-Wv9biM1nEPaUZH_8NoggiILItQ-Kz8nm6JoiGKOjLOKkisjJhl22FZ3KyfZAKSHx0Q9YYPjoWxHqLHsZYFq46yzgi-OHlYmAld3KK5UwrjfTgtv1rcgh51i029Vh5_syFEjvG1DfusDBUbuC8D0NtDqi7ipkwpAINwIzP1hbqdOdGWO8IA16TXN4LCuvMbg", "sourcePort": "8080", "HTTP Header": "HTTP/1.1 200 OK\\r\\n", "destPort": "56644"}
{"clientSecret": "250e42b8-3f41-4d0f-9b6b-e32e09fccaf7", "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJoWldPSWExUWJXczNWZjVDX2NpWTRsU1U0ZjRacHZWLXdKRHZHVkMtWXNnIn0.eyJqdGkiOiI3NDY0YTdjOC01NzQzLTRlNDYtOTEyMC01MzVkMTU5ZGQ3MjAiLCJleHAiOjE1MDg3NzU0NjQsIm5iZiI6MCwiaWF0IjoxNTA4NzczNjY0LCJpc3MiOiJodHRwOi8vMTkyLjE2OC45OS4xMDA6ODA4MC9hdXRoL3JlYWxtcy9DYW5ESUciLCJhdWQiOiJnYTRnaFNlcnZlciIsInN1YiI6IjhhMzViYWI0LWMxZTktNDUzNi1iOWEwLTViZjI5MDA0Y2RlYyIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJnYTRnaFNlcnZlciIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6IjFkMDA5NWE3LTg0MDEtNDYwYi1hMjAxLTEzMGM5MjdlODM0YiIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX19.Qeba3s9E_zjROppZxT5FL2Je0iQ7W4wpIPKW7I_TyImzdyxkHWxLjYxQFoSr1xA5rRa7QWVRwDfjli5xrFq5U1NLlvOBWkAaVrIMsiOAh8a5URLR1WnfTtcQF6-qyez64f-Sx5JY4U8oLhf0UsZAOo8yMMWYozkuB_7Lfv_D6GzGZatKqk-oWbWPdvjX5k-J-7x2T8dkwn7d07ZfAO8OghaxhD_zN0rEQuruwBx5Wl6vJpF5DqNvDX7TYUBturJb5-jKhN8juiP_HFCr6QET9k3DSLtxyD_wpmDOPp4_OY3-R6gYtFFRfzzdnBp8dm6Azj_q5oVldR_wX7Tncb3xAw", "packetSize": "1481", "clientId": "ga4ghServer", "destIP": "172.17.0.2", "sourceIP": "172.17.0.1", "sourcePort": "56648", "grantType": "refresh_token", "HTTP Header": "POST /auth/realms/CanDIG/protocol/openid-connect/token HTTP/1.1\\r\\n", "destPort": "8080"}
{"refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJoWldPSWExUWJXczNWZjVDX2NpWTRsU1U0ZjRacHZWLXdKRHZHVkMtWXNnIn0.eyJqdGkiOiJlYTUyMWI3My0xODA2LTRmYjUtOWUzYS1jZDA2OTdhZDQxMmQiLCJleHAiOjE1MDg3NzU3NjQsIm5iZiI6MCwiaWF0IjoxNTA4NzczOTY0LCJpc3MiOiJodHRwOi8vMTkyLjE2OC45OS4xMDA6ODA4MC9hdXRoL3JlYWxtcy9DYW5ESUciLCJhdWQiOiJnYTRnaFNlcnZlciIsInN1YiI6IjhhMzViYWI0LWMxZTktNDUzNi1iOWEwLTViZjI5MDA0Y2RlYyIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJnYTRnaFNlcnZlciIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6IjFkMDA5NWE3LTg0MDEtNDYwYi1hMjAxLTEzMGM5MjdlODM0YiIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX19.KGtnJab-3T31DX-QlifvSBARVVsNjZ6nyFMBpOd4soiXx-CV93zQa8eXKOfwHoHED4jFctilefROVfWU2kVlw_NpAhHsj0LTpLgTHPWUEa7GGc6V3iU1_yQaJwE7YMiDegcGp7L1aA7gISb8AGy3CvAwyveTPZiUZq4OOf47xtA6E_tw1Q_lKtu5QOmiAf8Lpbifk1R2ZhY5YuYOPTPQG4QfBA9P5yoIQ_-DptrKhj8emq_0nMrRupvXkHr3ySI0dF3y0wIObfK6z0uh26qdrDwuLURscaTnmSdoqycd1XiUUm4z2SI86sIqBsE2rUoIkK113oNoTdcvMmC-SZCjfQ", "tokenType": "bearer", "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJoWldPSWExUWJXczNWZjVDX2NpWTRsU1U0ZjRacHZWLXdKRHZHVkMtWXNnIn0.eyJqdGkiOiJiNjBhMDZmMS1mMWNhLTRiNzctODhjZi1mYTAyYWRmZGVkNGUiLCJleHAiOjE1MDg3NzQwMjQsIm5iZiI6MCwiaWF0IjoxNTA4NzczOTY0LCJpc3MiOiJodHRwOi8vMTkyLjE2OC45OS4xMDA6ODA4MC9hdXRoL3JlYWxtcy9DYW5ESUciLCJhdWQiOiJnYTRnaFNlcnZlciIsInN1YiI6IjhhMzViYWI0LWMxZTktNDUzNi1iOWEwLTViZjI5MDA0Y2RlYyIsInR5cCI6IkJlYXJlciIsImF6cCI6ImdhNGdoU2VydmVyIiwiYXV0aF90aW1lIjoxNTA4NzczNjY0LCJzZXNzaW9uX3N0YXRlIjoiMWQwMDk1YTctODQwMS00NjBiLWEyMDEtMTMwYzkyN2U4MzRiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6W10sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInByZWZlcnJlZF91c2VybmFtZSI6InVzZXIifQ.mMRQQsur1W9Nef-67gZKc71lB3laRuLb16uC7S-E7OqcypJs9cDwFLx1LVub_qL6WiyqczF9HMEhktq1rDaUWlwM-nXdPOjAQRB_C2pGDxX4Jl7iLoVf7x3OJKqoW6BWyDatXftl6oDg9k3TO0kjNot-2BD_VeW8703WXxF8tT4ZqeF3lwTlbrIF2Y1GDquS4O7pgoaugNJGcxIvH1GrJS_gJKcTlAut_9qkBw0V7IBdJagClp7jA1tq_NTcPqc4Dj8xwTVWKsQ_KShUZVtnE5ObAM8uHJ3I1mOriOvI6QsJY8__iM9Cn0Eh0PzT4aJfbWWtekUnHX0916g5rV_N9Q", "packetSize": "3582", "accessTokenExpiry": "60", "destIP": "172.17.0.1", "refreshTokenExpiry": "1800", "sourceIP": "172.17.0.2", "idToken": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJoWldPSWExUWJXczNWZjVDX2NpWTRsU1U0ZjRacHZWLXdKRHZHVkMtWXNnIn0.eyJqdGkiOiJjNDcwMTlmZS0zZjNiLTQ0Y2QtYjczYy0wOWI3MjMyNzM2YWQiLCJleHAiOjE1MDg3NzQwMjQsIm5iZiI6MCwiaWF0IjoxNTA4NzczOTY0LCJpc3MiOiJodHRwOi8vMTkyLjE2OC45OS4xMDA6ODA4MC9hdXRoL3JlYWxtcy9DYW5ESUciLCJhdWQiOiJnYTRnaFNlcnZlciIsInN1YiI6IjhhMzViYWI0LWMxZTktNDUzNi1iOWEwLTViZjI5MDA0Y2RlYyIsInR5cCI6IklEIiwiYXpwIjoiZ2E0Z2hTZXJ2ZXIiLCJhdXRoX3RpbWUiOjE1MDg3NzM2NjQsInNlc3Npb25fc3RhdGUiOiIxZDAwOTVhNy04NDAxLTQ2MGItYTIwMS0xMzBjOTI3ZTgzNGIiLCJhY3IiOiIxIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlciJ9.XtXEoUBvHZ5zrJqWDzbiyHMMA1ERvK3pw77AXnGUKy-m4yv7j_Qm0dTMEd-kovVPhvkSDDHIu-35QUl_8fdQpQHldQ97bKJDjAaZjAN8YyzObIYh0SMrJw-jAT8S_m-COzqpWb38H1iGlwa3jgdBz08maOI6KNepSVIbqfp2-sdxsHc1zgMCVnhBlcEcO144eerR0Hn20vTTrHaNy7bBSZncxGYhWxeFPT15yI34I7XHYe2_zHfas8KmBfZVkAuNhPK84CFC-Ixm0hnJDLK5hhh71_Ofg3ayitd2DlNqrX2vwbC59SBgy_4Q7P5dYzNFz4cBgHIUnMYfLlaHXX5EGg", "sourcePort": "8080", "HTTP Header": "HTTP/1.1 200 OK\\r\\n", "destPort": "56648"}

See example3.json for the JSON file.
