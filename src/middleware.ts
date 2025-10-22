/* eslint-disable no-console */

import { NextRequest, NextResponse } from 'next/server';

// import { getAuthInfoFromCookie } from '@/lib/auth'; // 暂时不需要这个导入，因为我们禁用了认证

export async function middleware(request: NextRequest) {
  // 直接放行所有请求，禁用所有访问控制
  return NextResponse.next();

  // 以下是原始的访问控制逻辑，已被禁用
  // const { pathname } = request.nextUrl;

  // // 跳过不需要认证的路径
  // if (shouldSkipAuth(pathname)) {
  //   return NextResponse.next();
  // }

  // const storageType = process.env.NEXT_PUBLIC_STORAGE_TYPE || 'localstorage';

  // if (!process.env.PASSWORD) {
  //   // 如果没有设置密码，重定向到警告页面
  //   const warningUrl = new URL('/warning', request.url);
  //   return NextResponse.redirect(warningUrl);
  // }

  // // 从cookie获取认证信息
  // const authInfo = getAuthInfoFromCookie(request);

  // if (!authInfo) {
  //   return handleAuthFailure(request, pathname);
  // }

  // // localstorage模式：在middleware中完成验证
  // if (storageType === 'localstorage') {
  //   if (!authInfo.password || authInfo.password !== process.env.PASSWORD) {
  //     return handleAuthFailure(request, pathname);
  //   }
  //   return NextResponse.next();
  // }

  // // 其他模式：只验证签名
  // // 检查是否有用户名（非localStorage模式下密码不存储在cookie中）
  // if (!authInfo.username || !authInfo.signature) {
  //   return handleAuthFailure(request, pathname);
  // }

  // // 验证签名（如果存在）
  // if (authInfo.signature) {
  //   const isValidSignature = await verifySignature(
  //     authInfo.username,
  //     authInfo.signature,
  //     process.env.PASSWORD || ''
  //   );

  //   // 签名验证通过即可
  //   if (isValidSignature) {
  //     return NextResponse.next();
  //   }
  // }

  // // 签名验证失败或不存在签名
  // return handleAuthFailure(request, pathname);
}

// 原始的辅助函数，现在不再被调用
// async function verifySignature(
//   data: string,
//   signature: string,
//   secret: string
// ): Promise<boolean> {
//   const encoder = new TextEncoder();
//   const keyData = encoder.encode(secret);
//   const messageData = encoder.encode(data);

//   try {
//     const key = await crypto.subtle.importKey(
//       'raw',
//       keyData,
//       { name: 'HMAC', hash: 'SHA-256' },
//       false,
//       ['verify']
//     );

//     const signatureBuffer = new Uint8Array(
//       signature.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
//     );

//     return await crypto.subtle.verify(
//       'HMAC',
//       key,
//       signatureBuffer,
//       messageData
//     );
//   } catch (error) {
//     console.error('签名验证失败:', error);
//     return false;
//   }
// }

// function handleAuthFailure(
//   request: NextRequest,
//   pathname: string
// ): NextResponse {
//   if (pathname.startsWith('/api')) {
//     return new NextResponse('Unauthorized', { status: 401 });
//   }

//   const loginUrl = new URL('/login', request.url);
//   const fullUrl = `${pathname}${request.nextUrl.search}`;
//   loginUrl.searchParams.set('redirect', fullUrl);
//   return NextResponse.redirect(loginUrl);
// }

// function shouldSkipAuth(pathname: string): boolean {
//   const skipPaths = [
//     '/_next',
//     '/favicon.ico',
//     '/robots.txt',
//     '/manifest.json',
//     '/icons/',
//     '/logo.png',
//     '/screenshot.png',
//     '/warning',
//   ];

//   return skipPaths.some((path) => pathname.startsWith(path));
// }

// 配置middleware匹配规则
export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|login|warning|api/login|api/register|api/logout|api/cron|api/server-config).*)/',
  ],
};
