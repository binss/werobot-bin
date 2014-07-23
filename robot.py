# -*- coding: utf-8 -*-

import werobot
import os
import inspect
import hashlib
import logging
from bottle import Bottle, request, response, abort, template
from six import PY3

from werobot.config import Config, ConfigAttribute
from werobot.parser import parse_user_msg
from werobot.reply import create_reply
from werobot.utils import to_binary

__all__ = ['BaseRoBot', 'WeRoBot']


# 默认配置（本地）
_DEFAULT_CONFIG = dict(
    SERVER="auto",
    HOST="127.0.0.1",
    PORT="8888"
)


class BaseRoBot(object):
    message_types = ['subscribe', 'unsubscribe', 'click',  # event
                     'text', 'image', 'link', 'location', 'voice']

    token = ConfigAttribute("TOKEN")
    session_storage = ConfigAttribute("SESSION_STORAGE")

    def __init__(self, token=None, logger=None, enable_session=True,
                 session_storage=None):
        self.config = Config(_DEFAULT_CONFIG)
        # 存放各类型处理函数的字典,键为类型，值为函数(用户通过handler添加)
        # 这里把各类型都作为键，并将值初始化为空数组
        self._handlers = dict((k, []) for k in self.message_types)
        self._handlers['all'] = []
        # 新建记录器
        if logger is None:
            import werobot.logger
            logger = werobot.logger.logger
        self.logger = logger

        # 如果允许session，启用之，并将之存进名为werobot_session的文件中
        if enable_session and session_storage is None:
            from .session.filestorage import FileStorage
            session_storage = FileStorage(
                filename=os.path.abspath("werobot_session")
            )
        # 更新配置
        self.config.update(
            TOKEN=token,
            SESSION_STORAGE=session_storage,

        )

    # 修饰符函数，指定修饰类型，用于指定需要处理消息类型
    # 处理所有类型消息
    def handler(self, f):
        """
        Decorator to add a handler function for every messages
        """
        self.add_handler(f, type='all')
        return f

    # 只处理文本消息
    def text(self, f):
        """
        Decorator to add a handler function for ``text`` messages
        """
        self.add_handler(f, type='text')
        return f

    # 只处理图像消息
    def image(self, f):
        """
        Decorator to add a handler function for ``image`` messages
        """
        self.add_handler(f, type='image')
        return f

    # 只处理位置消息
    def location(self, f):
        """
        Decorator to add a handler function for ``location`` messages
        """
        self.add_handler(f, type='location')
        return f

    # 只处理链接消息
    def link(self, f):
        """
        Decorator to add a handler function for ``link`` messages
        """
        self.add_handler(f, type='link')
        return f

    # 只处理语音消息
    def voice(self, f):
        """
        Decorator to add a handler function for ``voice`` messages
        """
        self.add_handler(f, type='voice')
        return f

    # 只处理被关注消息
    def subscribe(self, f):
        """
        Decorator to add a handler function for ``subscribe event`` messages
        """
        self.add_handler(f, type='subscribe')
        return f

    # 只处理被取消关注消息
    def unsubscribe(self, f):
        """
        Decorator to add a handler function for ``unsubscribe event`` messages
        """
        self.add_handler(f, type='unsubscribe')
        return f

    # 只处理菜单点击消息
    def click(self, f):
        """
        Decorator to add a handler function for ``click`` messages
        """
        self.add_handler(f, type='click')
        return f

    # 只处理菜单点击消息，可指定菜单名(key)
    def key_click(self, key):
        """
        Shortcut for ``click`` messages
        @key_click('KEYNAME') for special key on click event
        """
        def wraps(f):
            # inspect.getargspec(func)  return:(args, varargs, keywords, defaults)
            # args is a list of the argument names (it may contain nested lists). 
            # varargs and keywords are the names of the * and ** arguments or None. 
            # defaults is a tuple of default argument values or None if there are no default arguments.
            # 获取函数f的参数数目
            argc = len(inspect.getargspec(f).args)

            @self.click
            def onclick(message, session):
                if message.key == key:
                    return f(*[message, session][:argc])
            return f

        return wraps

    # 添加handler
    def add_handler(self, func, type='all'):
        """
        Add a handler function for messages of given type.
        """
        if not callable(func):
            raise ValueError("{} is not callable".format(func))

        # 把函数和其参数长度加到对应类型的key值列表中
        self._handlers[type].append((func, len(inspect.getargspec(func).args)))

    # 获取处理该类型的handler
    def get_handlers(self, type):
        return self._handlers[type] + self._handlers['all']

    # 获取返回的xml
    def get_reply(self, message):
        """
        Return the raw xml reply for the given message.
        """

        # 读取session
        session_storage = self.config["SESSION_STORAGE"]

        id = None
        session = None
        if session_storage and hasattr(message, "source"):
            id = to_binary(message.source)
            session = session_storage[id]

        # 获取处理该信息的所有handler
        handlers = self.get_handlers(message.type)
        try:
            for handler, args_count in handlers:
                # 从list[...]中取args_count个构成新list
                args = [message, session][:args_count]
                reply = handler(*args)
                if session_storage and id:
                    session_storage[id] = session
                if reply:
                    return reply
        except:
            self.logger.warning("Catch an exception", exc_info=True)

    # 校验签名
    # 加密/校验流程如下：
    #     1. 将token、timestamp、nonce三个参数进行字典序排序
    #     2. 将三个参数字符串拼接成一个字符串进行sha1加密
    #     3. 开发者获得加密后的字符串可与signature对比，标识该请求来源于微信
    def check_signature(self, timestamp, nonce, signature):
        sign = [self.config["TOKEN"], timestamp, nonce]
        sign.sort()
        sign = to_binary(''.join(sign))
        sign = hashlib.sha1(sign).hexdigest()
        return sign == signature

# 继承BaseRoBot
class WeRoBot(BaseRoBot):

    # 错误返回页面(直接访问时显示)
    ERROR_PAGE_TEMPLATE = """
    <!DOCTYPE html>
    <html>
        <head>
            <meta charset="utf8" />
            <title>Error: {{e.status}}</title>
            <style type="text/css">
              html {background-color: #eee; font-family: sans;}
              body {background-color: #fff; border: 1px solid #ddd;
                    padding: 15px; margin: 15px;}
              pre {background-color: #eee; border: 1px solid #ddd; padding: 5px;}
            </style>
        </head>
        <body>
            <h1>Error: {{e.status}}</h1>
            <p>微信机器人不可以通过 GET 方式直接进行访问。</p>
            <p>想要使用本机器人，请在微信后台中将 URL 设置为 <pre>{{request.url}}</pre> 并将 Token 值设置正确。</p>

            <p>如果你仍有疑问，请<a href="http://werobot.readthedocs.org/en/%s/">阅读文档</a>
        </body>
    </html>
    """ % werobot.__version__

    # @property可将函数当作属性访问
    @property
    def wsgi(self):
        if not self._handlers:
            raise
        # Bottle是微型Web框架
        app = Bottle()

        # bin add
        @app.route('/callback/:call_type/:id')
        def callback(call_type = '',id = '0'):
            # return 'Hello {}!'.format(open_id)
            import callback
            if call_type == 'check_new':
                callback.checkNewScore(id)
                return 'done'
            if call_type == 'check_term':
                callback.checkTermScore(id)
                return 'done' 
            if call_type == 'new_student':
                callback.newStudentInit(id)
                return 'done' 
            return 'fail'






        @app.get('<t:path>')
        def echo(t):
            if not self.check_signature(
                request.query.timestamp,
                request.query.nonce,
                request.query.signature
            ):
                return abort(403)
            return request.query.echostr

        @app.post('<t:path>')
        def handle(t):
            if not self.check_signature(
                request.query.timestamp,
                request.query.nonce,
                request.query.signature
            ):
                return abort(403)

            body = request.body.read()
            message = parse_user_msg(body)
            logging.info("Receive message %s" % message)
            reply = self.get_reply(message)
            if not reply:
                self.logger.warning("No handler responded message %s"
                                    % message)
                return ''
            response.content_type = 'application/xml'
            return create_reply(reply, message=message)

        @app.error(403)
        def error403(error):
            return template(self.ERROR_PAGE_TEMPLATE,
                            e=error, request=request)

        return app

    # 导入配置并运行
    def run(self, server=None, host=None,
            port=None, enable_pretty_logging=True):
        if enable_pretty_logging:
            from werobot.logger import enable_pretty_logging
            enable_pretty_logging(self.logger)
        if server is None:
            server = self.config["SERVER"]
        if host is None:
            host = self.config["HOST"]
        if port is None:
            port = self.config["PORT"]
        self.wsgi.run(server=server, host=host, port=port)
