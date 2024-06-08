//###
//# Licensed under the Apache License, Version 2.0 (the "License");
//# you may not use this file except in compliance with the License.
//# You may obtain a copy of the License at
//# 
//#      http://www.apache.org/licenses/LICENSE-2.0
//# 
//# Unless required by applicable law or agreed to in writing, software
//# distributed under the License is distributed on an "AS IS" BASIS,
//# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//# See the License for the specific language governing permissions and
//# limitations under the License.
//###

//###
//# Acknowledge: It is forked from https://github.com/unsigned6/notificator
//###

//#################################################################################################################################
// File name: Rabbit.js
//
// Ver           Date            Author          Comment
// =======       ===========     ===========     ==========================================
// V1.0.00       2020-07-20      Yurii Vlasiuk   Driver of RabbitMQ broker.
// V1.0.01       2022-08-09      DW              - Add license section.
//                                               - Modify some console displaying messages.
//                                               - Set channel prefetch count to 1. 
// V1.0.02       2024-05-01      DW              Remove message content from console log for security.
//#################################################################################################################################


const amqp = require('amqplib/callback_api');
const {
    formatMessage,
    parseMessage
} = require('../utils');
const PubSubDriverInterface = require('./PubSubDriverInterface');

class Rabbit extends PubSubDriverInterface {
    constructor(args) {
        super(args);
        if (!args.endpoint) throw new Error('"endpoint" is required');
        if (!args.login) throw new Error('"login" is required');
        if (!args.password) throw new Error('"password" is required');
        this.isReconnecting = false;
        this.endpoint = args.endpoint;
        this.login    = args.login;
        this.password = args.password;
    }

    async connect() {
        const connectString = `amqp://${this.login}:${this.password}@${this.endpoint}`;

        try {
            this.connection = await new Promise((res, rej) => {
                amqp.connect(connectString, (error, connection) => {
                    if (error) return rej(error);

                    console.info(`Connected to RabbitMQ on ${this.endpoint}`);
                    res(connection);
                });
            });
        } catch (error) {
            console.error(`Failed to connect to ${this.endpoint}`);
            await new Promise(res => setTimeout(() => res(), 5000));
            console.info('Trying to reconnect...');

            return this.connect();
        }

        this.connection.on('error', (error) => {
            if (error.message !== 'Connection closing') {
                console.error('[AMQP] conn error');
                console.error(error);
                this.isReconnecting = true;

                return setTimeout(this.connect.bind(this), 5000);
            }
        });
        this.connection.on('close', () => {
            console.warn('[AMQP] reconnecting started');
            this.isReconnecting = true;

            return setTimeout(this.connect.bind(this), 5000);
        });

        if (this.isReconnecting) {
            await this._recreateChannels();
            await this._reassignHandlers();
            console.info('Reconnected successfully.');
            this.isReconnecting = false;
        }

        return this.connection;
    }

    async _recreateChannels() {
        console.info('Recreating channels...');
        for (const channelName in this.channels) {
            if (!this.channels[channelName]) continue;
            await this.createChannel(channelName);
        }
        console.info('Recreating channels completed.');
    }

    _reassignHandlers() {
        console.info('Reassigning handlers...');
        for (const channelName in this.handlers) {
            if (!this.handlers[channelName]) continue;
            console.info(`For channel: "${channelName}"`);
            for (const handler of this.handlers[channelName]) {
                console.info(`Subscribing for handler: "${handler.name}"`);
                this.subscribe(channelName, handler, true);
            }
        }
        console.info('Reassign handlers completed.');
    }

    async createChannel(channelName, pubsubMode = true) {
        this.channels[channelName] = await new Promise((res, rej) => {
            this.connection.createChannel((error, channel) => {
                if (error) {
                    console.error(`Failed to create channel "${channelName}"`);

                    return rej(error);
                }

                console.info(`Created channel "${channelName}"`);
                res(channel);
            });
        });

        this.channels[channelName].assertExchange(channelName, 'fanout', { durable: false });

        if (!this.handlers[channelName]) this.handlers[channelName] = [];

        return this.channels[channelName];
    }

    publish(exchange, message) {
        try {
            const formattedMessage = formatMessage(message);

            console.info(`Publishing message to channel "${exchange}"`);
            if (!this.channels[exchange]) throw Error(`Channel for exchange ${exchange} not exists`);
            this.channels[exchange].publish(exchange, '', Buffer.from(formattedMessage));
        } catch (error) {
            if (!this.isReconnecting && error.message === 'Channel closed') {
                this.isReconnecting = true;
                this.connect();
            }
            throw error;
        }
    }

    subscribe(exchange, messageHandler, isReconnecting = false) {
        if (!this.channels[exchange]) throw Error(`Channel for queue ${exchange} not exists`);

        this.channels[exchange].assertQueue('', { exclusive: true }, (error2, q) => {
            if (error2) throw error2;

            console.info(` [*] Notificator is waiting messages for ${exchange}.`);
            this.channels[exchange].bindQueue(q.queue, exchange, '');

            // 2022-08-09 DW: Fetch one message each time to prevent data lost on heavy workload. 
            this.channels[exchange].prefetch(1);

            this.channels[exchange].consume(q.queue, (message) => {
                this._messageHanler({ exchange, message, noAck: true }, messageHandler);
            }, { noAck: true });
        });
        if (!isReconnecting) this.handlers[exchange].push(messageHandler);
    }

    close() {
        console.log('close()');
        this.connection.close();
        console.info('Closed connection.');
    }

    _messageHanler({ queue, message, noAck = false }, messageHandler) {
        const messageString = message.content.toString();

        console.info(` [x] Message received ...`);
        if (typeof messageHandler === 'function') messageHandler(parseMessage(messageString));
        if (noAck) return;

        setTimeout(() => {
            console.info(' [x] Done');
            this.channels[queue].ack(message);
        }, 1000);
    }
}

module.exports = Rabbit;
