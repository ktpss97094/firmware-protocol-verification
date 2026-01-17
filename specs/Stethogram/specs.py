"""
Stethogram AT Command Escape Sequence Spec

1. send_escape_sequence() 執行時:
    (1) 此次發送距離上一次 UART 傳輸結束的時間間隔必須 >= 1 秒
    (2) 發送內容須為 +++
    (3) 發送結束後，距離下一次 UART 傳輸開始的時間間隔必須 >= 1 秒
"""
