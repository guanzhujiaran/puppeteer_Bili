/*
 * @Author: 星瞳 1944637830@qq.com
 * @Date: 2024-04-08 17:30:39
 * @LastEditors: 星瞳 1944637830@qq.com
 * @LastEditTime: 2024-05-31 22:11:00
 * @FilePath: \tampermonkey\ExpressServerEnd\RouteModules\JwtModule.js
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
//用一个单独模块来放生成token和验证token的方法，方便后面调用。
const config = require("@/ExpressServerEnd/config");
const secretKey = config.common_config.salt.jwt_secret;
const jwt = require("jsonwebtoken");
const expressJwt = require("express-jwt");
const { user_redis_dao } = require("@/ExpressServerEnd/DAO/UserRedisDao");

// JWT 存储：浏览器直连的服务端写入 HttpOnly + Secure Cookie，
// 替代前端 localStorage（防 XSS 窃取）。Cookie 名固定为 bili_jwt。
const COOKIE_NAME = "bili_jwt";

// 从 HttpOnly Cookie 或 Authorization 头提取 JWT（前端不再使用 localStorage）
function getToken(req) {
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    const m = cookieHeader.match(/(?:^|;\s*)bili_jwt=([^;]+)/);
    if (m) {
      const v = decodeURIComponent(m[1]);
      if (v) return v;
    }
  }
  // const auth = req.headers.authorization;
  // if (auth && auth.startsWith("Bearer ")) return auth.slice(7);
  // return auth || undefined;
}

// Cookie secure 开关：缺省按环境（production=true / development=false），
// 可用 JWT_COOKIE_SECURE 环境变量强制覆盖（开发环境 HTTP 下置 false）。
function cookieSecure() {
  const env = process.env.JWT_COOKIE_SECURE;
  if (env !== undefined) return env === "true";
  return process.env.NODE_ENV === "production";
}

function setJwtCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: cookieSecure(),
    sameSite: "lax",
    path: "/",
    maxAge: 15 * 24 * 3600 * 1000,
  });
}

function clearJwtCookie(res) {
  res.cookie(COOKIE_NAME, "", {
    httpOnly: true,
    secure: cookieSecure(),
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
}

const on_expired = async (req, err) => {
  throw err;
};
const is_revoked = async (req, token) => {
  return !!(await user_redis_dao.is_jwt_signature_in_black_list({
    signature: token.signature,
  }));
};
//生成 token
/**
 *
 * @param payload {Object}
 * @param payload.uid {number}
 * @param payload.level {string} - 角色：0,1,2,3,4,5,6 还有一个超级root
 * @return {string}
 */
const createToken = (payload) =>
  jwt.sign(payload, secretKey, {
    expiresIn: 15 * 24 * 3600, // 设置token的有效期 单位（秒）
    algorithm: "HS256",
  });

// 验证 token（必须登录）
const jwtAuth = expressJwt
  .expressjwt({
    secret: secretKey,
    algorithms: ["HS256"],
    credentialsRequired: true, // true：必须校验
    requestProperty: "auth", // 全站（含 express-jwt-permissions、UserService.logout）均按 req.auth 取身份
    getToken: getToken, // 优先从 HttpOnly Cookie 读取（前端不再使用 localStorage）
    onExpired: on_expired,
    isRevoked: is_revoked,
  })
  .unless({
    path: [
      "/api/v1/user/login",
      "/api/v1/user/reg",
      "/api/admin/queues",
      "/api/v1/ping",
      { url: /api\/admin\/queues\/.*/ },
      { url: /api\/v1\/feedback\/comment\/reply\/main/ },
      { url: /api\/v1\/feedback\/comment\/reply\/reply/ },
      { url: /api\/v1\/samsClub\/.*/ },
      { url: /api\/v1\/casdoor\/.*/ },
      { url: /api\/v1\/lottery_database\/bili\/.*/ },
      // 动态 Feed / 详情对未登录用户同样可读（be-message-service 侧不强制登录，
      // viewer_mid 缺失时仅不展示点赞态）；写接口仍由上游 RequiredUser 校验。
      { url: /\/api\/v1\/community\/feed\/all/ },
      { url: /\/api\/v1\/community\/feed\/space\/.*/ },
      { url: /\/api\/v1\/community\/detail\/.*/ },
      { url: /\/api\/v1\/community\/details/ },
      // 话题广场 / 热门话题：公开可读（对标 B 站话题广场，匿名可浏览发现流）；
      // 后端 /topic/square、/topic/hot-search 已改用 OptionalUser，匿名时上游拿空 mid 不报错。
      { url: /\/api\/v1\/community\/topic\/square/ },
      { url: /\/api\/v1\/community\/topic\/hot-search/ },
      // 动态点赞明细 / 转发列表：公开可读，对齐 detail 接口策略
      { url: /\/api\/v1\/community\/.*\/likers/ },
      { url: /\/api\/v1\/community\/.*\/forwards/ },
      // 互动态查询（批量 / detail 单资源）：公开可读（计划书 §5.18，2.60.0）。
      // be-message-service 侧已改用 OptionalUser，匿名时 viewer_mid=0 → isLike /
      // isFavorite 恒 false，计数照常返回；浏览 MQ 仍仅登录用户投递。
      // 正则未锚定，一条同时覆盖 /interaction/status 与 /interaction/status/{bizId}。
      { url: /\/api\/v1\/community\/interaction\/status/ },
      // 评论读接口（列表 / 详情 / 楼中楼 / 首页最新评论）对未登录用户同样可读：
      // be-message-service 侧 resolve_optional_viewer 已允许匿名，匿名时后端强制最多
      // 10 条并返回 viewer_is_anonymous 标记，前端渲染登录引导蒙层（对标 B 站）。
      // 评论写接口（add / reply / delete / audit 等）不在白名单，仍走 jwtAuth + 上游 RequiredUser。
      { url: /\/api\/v1\/comment\/main/ },
      { url: /\/api\/v1\/comment\/detail\/.*/ },
      { url: /\/api\/v1\/comment\/sub/ },
      { url: /\/api\/v1\/comment\/latest/ },
      // 收藏公开读接口：访客查看他人主页收藏（无需登录，受主人 showFavorites 控制）
      { url: /\/api\/v1\/favorite\/user\/folders/ },
      { url: /\/api\/v1\/favorite\/user\/dynamics/ },
      // 用户空间信息：公开可读（对标 B 站 /x/space/wbi/acc/info）。
      // 匿名返回公开资料；登录时上游结合 x-bili-mid 做黑名单互访拒绝（403）。
      { url: /\/api\/v1\/user\/space\/info/ },
    ], //不需要校验的路径
  });

// 可选登录的 JWT 验证中间件
const jwtAuthOptional = expressJwt.expressjwt({
  secret: secretKey,
  algorithms: ["HS256"],
  credentialsRequired: false, // false：可选校验，有token就解析，没有也不报错
  requestProperty: "auth", // 全站（含 express-jwt-permissions、UserService.logout）均按 req.auth 取身份
  getToken: getToken, // 优先从 HttpOnly Cookie 读取（前端不再使用 localStorage）
  onExpired: on_expired,
  isRevoked: is_revoked,
});
const jwtAuthGenerator = ({ credentialsRequired = true }) => {
  return expressJwt.expressjwt({
    secret: secretKey,
    algorithms: ["HS256"],
    credentialsRequired: credentialsRequired, //  false：不校验
    requestProperty: "auth", // 全站（含 express-jwt-permissions、UserService.logout）均按 req.auth 取身份
    getToken: getToken, // 优先从 HttpOnly Cookie 读取（前端不再使用 localStorage）
    onExpired: on_expired,
    isRevoked: is_revoked,
  });
};

module.exports = { jwtAuth, createToken, jwtAuthGenerator, jwtAuthOptional, getToken, setJwtCookie, clearJwtCookie };

