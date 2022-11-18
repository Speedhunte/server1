#pragma once

enum MessageType //Тип сообщения
{
    kMessage,
    kStatus,
    kInfo,
    kUsername,
    kInvalidUsername,
    kUserAdded,
    kUserRemoved,
    kHello,
    kInvalidHello
};

enum Status //Статус пользователя
{
    kAvailable,
    kMovedAway,
    kDoNotDisturb
};

constexpr char CIPHER_NAME[] = "DHE-PSK-AES256-GCM-SHA384"; //алгоритм шифрования, с помощью которого шируется соединение
