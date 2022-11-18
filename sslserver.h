#pragma once

#include <QTcpServer>
#include <QPointer>
#include <QDateTime>
#include <QSslSocket>

#include <unordered_map>

#include "global.h"

class QSslSocket;

template <>
struct std::hash <QPointer <QSslSocket> >
{
    //Перегрузка структуры hash для QPointer <QSslSoclet>, нужно, чтобы объекты этого типа могли быть ключами в unordered_map
    // -> std::unordered_map <QPointer <QSslSocket>, SocketInfo> sockets_
    size_t operator()(QPointer <QSslSocket> const &p) const
    {
        std::hash <int *> hasher;
        return hasher((int *)p.data());
    }
};

class SslServer : public QTcpServer
{
    Q_OBJECT
public:
    explicit SslServer(QObject *parent = nullptr);
    ~SslServer();

protected:
    virtual void incomingConnection(qintptr socket_escriptor) override;

private:
    struct SocketInfo
    {
        //Структура хранит данные о кокнкретном клиенте
        QString username_;
        QDateTime connect_date_time_;
        Status status_;
        QString ip_;
    };

    void ProcessMessage(QSslSocket *socket, QDataStream &in);
    void ProcessStatus(QSslSocket *socket, QDataStream &in);
    void ProcessUsername(QSslSocket *socket, QDataStream &in);

    std::unordered_map <QPointer <QSslSocket>, SocketInfo> sockets_;

signals:
    void UserAdded(QString const &username);
    void UserRemoved(QString const &username);
    void UserStatusChanged(QString const &username, Status status);
    void UsernameChanged(QString const &old_username, QString const &new_username);
    void MessageReceived(QString const &ip, QString const &username, QString const &date_time, QString const &msg);
    void ConnectionError();
    void SslError();
    void CryptError();

private slots:
    void ReadyForUsername();
    void Ready();
    void Read();
    void Disconnect();
};
