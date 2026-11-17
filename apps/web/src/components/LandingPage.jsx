import React, { useEffect, useRef } from 'react';

export default function LandingPage({ onLaunchConsole }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    let animId = null;
    let cleanupFn = () => {};

    // Scroll reveal observer
    const reveals = document.querySelectorAll('[data-reveal]');
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('in');
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.18, rootMargin: '0px 0px -8% 0px' }
    );
    reveals.forEach((el) => observer.observe(el));

    // Three.js 3D WebGL Planet Setup
    async function initPlanet() {
      try {
        const THREE = await import(/* @vite-ignore */ 'https://unpkg.com/three@0.143.0/build/three.module.js');
        const { EffectComposer } = await import(/* @vite-ignore */ 'https://unpkg.com/three@0.143.0/examples/jsm/postprocessing/EffectComposer.js');
        const { RenderPass } = await import(/* @vite-ignore */ 'https://unpkg.com/three@0.143.0/examples/jsm/postprocessing/RenderPass.js');
        const { UnrealBloomPass } = await import(/* @vite-ignore */ 'https://unpkg.com/three@0.143.0/examples/jsm/postprocessing/UnrealBloomPass.js');
        const { ShaderPass } = await import(/* @vite-ignore */ 'https://unpkg.com/three@0.143.0/examples/jsm/postprocessing/ShaderPass.js');
        const { GammaCorrectionShader } = await import(/* @vite-ignore */ 'https://unpkg.com/three@0.143.0/examples/jsm/shaders/GammaCorrectionShader.js');
        const { CopyShader } = await import(/* @vite-ignore */ 'https://unpkg.com/three@0.143.0/examples/jsm/shaders/CopyShader.js');
        const { GLTFLoader } = await import(/* @vite-ignore */ 'https://unpkg.com/three@0.143.0/examples/jsm/loaders/GLTFLoader.js');
        const { DRACOLoader } = await import(/* @vite-ignore */ 'https://unpkg.com/three@0.143.0/examples/jsm/loaders/DRACOLoader.js');

        if (!canvasRef.current) return;
        const canvas = canvasRef.current;

        const CONFIG = {
          rimColor: '#c1faff', rimPower: 2.4, nightLights: 10, terrainDepth: 0.33, terrainShade: 1.3,
          oceanGlint: 0.45, oceanDeep: 0.12, oceanFlow: 3, oceanFlowSpeed: 0.8, oceanFlowScale: 2.1,
          glowColor: '#3a6cff', glowIntensity: 3.35, planetRadius: 1.95, spin: 0.03, initRotation: 2.07,
          tilt: 0.37, autoRotate: 0,
          cloud1Height: 1.005, cloud1Opacity: 0.6, cloud1Spin: 0.06,
          cloud2Height: 1.03, cloud2Opacity: 0.5, cloud2Spin: 0.14,
          cloud3Height: 1.075, cloud3Opacity: 0.5, cloud3Spin: 0.1,
          bgColor: '#040a1e', flameColor: '#3a6cff', flameColor2: '#c1faff', flameAmt: 0.15,
          atmoColor: '#9fc4ff', atmoCount: 320, atmoSize: 22, atmoSpeed: 0.8,
          starColor: '#cfe0ff', starCount: 1400, starSize: 1.6, starFlicker: 1,
          markerColor: '#ffd27a', markerCount: 60, markerSize: 16, markerSpeed: 0.5,
        };
        const LAYERS = { NONE: 0, TORUS_SCENE: 1, BLOOM_SCENE: 2, ENTIRE_SCENE: 3 };

        const Lerp = (a, b, t) => a + (b - a) * t;
        const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
        const hexToVec3 = (hex) => {
          const c = new THREE.Color(hex);
          return new THREE.Vector3(c.r, c.g, c.b);
        };
        function sample(stops, p) {
          if (p <= stops[0].p) return stops[0].v;
          if (p >= stops[stops.length - 1].p) return stops[stops.length - 1].v;
          for (let i = 0; i < stops.length - 1; i++) {
            const s0 = stops[i], s1 = stops[i + 1];
            if (p >= s0.p && p <= s1.p) {
              let t = (p - s0.p) / (s1.p - s0.p);
              t = t * t * (3 - 2 * t);
              return Lerp(s0.v, s1.v, t);
            }
          }
          return stops[0].v;
        }

        const SNOISE = `
        vec4 permute(vec4 x){return mod(((x*34.0)+1.0)*x, 289.0);}
        vec4 taylorInvSqrt(vec4 r){return 1.79284291400159 - 0.85373472095314 * r;}
        float snoise(vec3 v){
          const vec2 C = vec2(1.0/6.0, 1.0/3.0); const vec4 D = vec4(0.0, 0.5, 1.0, 2.0);
          vec3 i = floor(v + dot(v, C.yyy)); vec3 x0 = v - i + dot(i, C.xxx);
          vec3 g = step(x0.yzx, x0.xyz); vec3 l = 1.0 - g;
          vec3 i1 = min(g.xyz, l.zxy); vec3 i2 = max(g.xyz, l.zxy);
          vec3 x1 = x0 - i1 + 1.0 * C.xxx; vec3 x2 = x0 - i2 + 2.0 * C.xxx; vec3 x3 = x0 - 1.0 + 3.0 * C.xxx;
          i = mod(i, 289.0);
          vec4 p = permute(permute(permute(i.z + vec4(0.0, i1.z, i2.z, 1.0)) + i.y + vec4(0.0, i1.y, i2.y, 1.0)) + i.x + vec4(0.0, i1.x, i2.x, 1.0));
          float n_ = 1.0/7.0; vec3 ns = n_ * D.wyz - D.xzx;
          vec4 j = p - 49.0 * floor(p * ns.z *ns.z);
          vec4 x_ = floor(j * ns.z); vec4 y_ = floor(j - 7.0 * x_);
          vec4 x = x_ *ns.x + ns.yyyy; vec4 y = y_ *ns.x + ns.yyyy; vec4 h = 1.0 - abs(x) - abs(y);
          vec4 b0 = vec4(x.xy, y.xy); vec4 b1 = vec4(x.zw, y.zw);
          vec4 s0 = floor(b0)*2.0 + 1.0; vec4 s1 = floor(b1)*2.0 + 1.0; vec4 sh = -step(h, vec4(0.0));
          vec4 a0 = b0.xzyw + s0.xzyw*sh.xxyy; vec4 a1 = b1.xzyw + s1.xzyw*sh.zzww;
          vec3 p0 = vec3(a0.xy,h.x); vec3 p1 = vec3(a0.zw,h.y); vec3 p2 = vec3(a1.xy,h.z); vec3 p3 = vec3(a1.zw,h.w);
          vec4 norm = taylorInvSqrt(vec4(dot(p0,p0), dot(p1,p1), dot(p2, p2), dot(p3,p3)));
          p0 *= norm.x; p1 *= norm.y; p2 *= norm.z; p3 *= norm.w;
          vec4 m = max(0.5 - vec4(dot(x0,x0), dot(x1,x1), dot(x2,x2), dot(x3,x3)), 0.0); m = m * m;
          return 42.0 * dot(m*m, vec4(dot(p0,x0), dot(p1,x1), dot(p2,x2), dot(p3,x3)));
        }
        `;

        const FinalPass = {
          uniforms: {
            iTime: { value: 0 },
            tDiffuse: { value: null },
            torusTexture: { value: null },
            bloomTexture: { value: null },
            haloTexture: { value: null },
            uBg: { value: hexToVec3(CONFIG.bgColor) },
            uFlameA: { value: hexToVec3(CONFIG.flameColor) },
            uFlameB: { value: hexToVec3(CONFIG.flameColor2) },
            uFlameAmt: { value: CONFIG.flameAmt },
          },
          vertexShader: `varying vec2 vUv; void main(){ vUv = uv; gl_Position = vec4(position, 1.0); }`,
          fragmentShader: `
            uniform float iTime; uniform sampler2D tDiffuse; uniform sampler2D bloomTexture; uniform sampler2D torusTexture; uniform sampler2D haloTexture;
            uniform vec3 uBg; uniform vec3 uFlameA; uniform vec3 uFlameB; uniform float uFlameAmt;
            varying vec2 vUv;
            vec3 warp3d(vec3 pos, float t){ float curv=.8,a=1.9,b=0.7; pos*=2.;
              pos.x+=curv*sin(t+a*pos.y)+t*b; pos.y+=curv*cos(t+a*pos.x);
              pos.y+=curv*sin(t+a*pos.z)+t*b; pos.z+=curv*cos(t+a*pos.y);
              pos.z+=curv*sin(t+a*pos.x)+t*b; pos.x+=curv*cos(t+a*pos.z);
              return 0.5+0.5*cos(pos.xyz+vec3(1,2,4)); }
            void main(){
              vec2 uv = 2.*vUv - 1.;
              vec3 w = pow(warp3d(vec3(uv.x, sin(uv.y), uv.y), iTime*1.5), vec3(1.5));
              vec3 flame = 1.5*uFlameA*w.x; flame*=w.y; flame += uFlameB*w.z;
              flame *= smoothstep(0.25, 1., abs(uv.y));
              float md = smoothstep(-0.7, 1., -uv.y*uv.x); flame *= md*md;
              vec3 bg = uBg * (1.0 - 0.4 * length(uv));
              vec3 halo = texture2D(haloTexture, vUv).xyz;
              gl_FragColor = vec4(bg + flame*uFlameAmt + texture2D(bloomTexture, vUv).xyz + texture2D(torusTexture, vUv).xyz + texture2D(tDiffuse, vUv).xyz + halo, 1.);
            }`,
        };

        let width = window.innerWidth;
        let height = window.innerHeight;

        const renderer = new THREE.WebGL1Renderer({ canvas, antialias: true });
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        renderer.setSize(width, height);
        renderer.outputEncoding = THREE.sRGBEncoding;
        renderer.shadowMap.enabled = true;
        renderer.shadowMap.type = THREE.VSMShadowMap;

        const scene = new THREE.Scene();
        scene.background = new THREE.Color(0x000000);

        const camera = new THREE.PerspectiveCamera(40, width / height, 0.1, 200);
        camera.position.set(0, 0, 8);
        camera.layers.enable(LAYERS.TORUS_SCENE);
        camera.layers.enable(LAYERS.BLOOM_SCENE);
        camera.layers.enable(LAYERS.ENTIRE_SCENE);
        scene.add(camera);

        const ambientLight = new THREE.AmbientLight(0xffffff, 1.8);
        ambientLight.layers.enable(LAYERS.TORUS_SCENE);
        ambientLight.layers.enable(LAYERS.BLOOM_SCENE);
        ambientLight.layers.enable(LAYERS.ENTIRE_SCENE);
        scene.add(ambientLight);

        const dirLight = new THREE.DirectionalLight(0xffffff, 0.8);
        dirLight.position.set(0, 10, 2);
        dirLight.layers.enable(LAYERS.TORUS_SCENE);
        dirLight.layers.enable(LAYERS.BLOOM_SCENE);
        dirLight.layers.enable(LAYERS.ENTIRE_SCENE);
        scene.add(dirLight);

        // Composers
        const torusComposer = new EffectComposer(renderer);
        torusComposer.renderToScreen = false;
        torusComposer.addPass(new RenderPass(scene, camera));
        torusComposer.addPass(new ShaderPass(GammaCorrectionShader));
        torusComposer.addPass(new UnrealBloomPass(new THREE.Vector2(width, height), 0.22, 0.2, 0));
        torusComposer.addPass(new ShaderPass(CopyShader));

        const bloomComposer = new EffectComposer(renderer);
        bloomComposer.renderToScreen = false;
        bloomComposer.addPass(new RenderPass(scene, camera));
        bloomComposer.addPass(new UnrealBloomPass(new THREE.Vector2(width, height), 0.5, 0.6, 0));
        bloomComposer.addPass(new ShaderPass(GammaCorrectionShader));

        const finalComposer = new EffectComposer(renderer);
        finalComposer.addPass(new RenderPass(scene, camera));
        const finalPass = new ShaderPass(FinalPass);
        finalComposer.addPass(finalPass);

        finalPass.uniforms.bloomTexture.value = bloomComposer.renderTarget1.texture;
        finalPass.uniforms.torusTexture.value = torusComposer.renderTarget1.texture;

        const STOPS_X = [{ p: 0, v: 0 }, { p: 0.32, v: -3.1 }, { p: 0.64, v: 3.2 }, { p: 1, v: 0 }];
        const STOPS_Y = [{ p: 0, v: -4.5 }, { p: 0.32, v: 0.55 }, { p: 0.64, v: 0.45 }, { p: 1, v: 0.15 }];
        const STOPS_S = [{ p: 0, v: 2.15 }, { p: 0.32, v: 1.0 }, { p: 0.64, v: 0.92 }, { p: 1, v: 1.12 }];

        const worldGroup = new THREE.Group();
        const planetGroup = new THREE.Group();
        planetGroup.rotation.z = CONFIG.tilt;
        const cloudGroup = new THREE.Group();
        cloudGroup.rotation.z = CONFIG.tilt;
        cloudGroup.visible = false;

        worldGroup.add(planetGroup);
        worldGroup.add(cloudGroup);
        scene.add(worldGroup);

        worldGroup.position.set(STOPS_X[0].v, STOPS_Y[0].v, 0);
        worldGroup.scale.setScalar(STOPS_S[0].v);

        // Atmosphere halo glow
        const glowGeo = new THREE.PlaneGeometry(2, 2);
        const glowMat = new THREE.ShaderMaterial({
          uniforms: {
            uGlow: { value: hexToVec3(CONFIG.glowColor) },
            uIntensity: { value: CONFIG.glowIntensity },
          },
          vertexShader: `varying vec2 vUv; void main(){ vUv=uv; gl_Position = projectionMatrix*modelViewMatrix*vec4(position,1.0); }`,
          fragmentShader: `
            uniform vec3 uGlow; uniform float uIntensity; varying vec2 vUv;
            void main(){
              float d = length(vUv - 0.5) * 2.0;
              float a = pow(clamp(1.0 - d, 0.0, 1.0), 2.2);
              gl_FragColor = vec4(uGlow * a * uIntensity, a);
            }
          `,
          transparent: true,
          depthWrite: false,
          side: THREE.DoubleSide,
          blending: THREE.AdditiveBlending,
        });
        const glowMesh = new THREE.Mesh(glowGeo, glowMat);
        glowMesh.scale.setScalar(CONFIG.planetRadius * 2.3);
        glowMesh.layers.enable(LAYERS.ENTIRE_SCENE);
        glowMesh.layers.enable(LAYERS.BLOOM_SCENE);
        worldGroup.add(glowMesh);

        // Starfield
        const starGeo = new THREE.BufferGeometry();
        const starPos = [];
        const starSeed = [];
        const starBright = [];
        for (let i = 0; i < CONFIG.starCount; i++) {
          const u = Math.random();
          const v = Math.random();
          const theta = u * 2.0 * Math.PI;
          const phi = Math.acos(2.0 * v - 1.0);
          const r = 90.0;
          const sinPhi = Math.sin(phi);
          starPos.push(r * sinPhi * Math.cos(theta), r * sinPhi * Math.sin(theta), r * Math.cos(phi));
          starSeed.push(Math.random() * 50.0);
          starBright.push(0.35 + Math.random() * 0.65);
        }
        starGeo.setAttribute('position', new THREE.Float32BufferAttribute(starPos, 3));
        starGeo.setAttribute('seed', new THREE.Float32BufferAttribute(starSeed, 1));
        starGeo.setAttribute('bright', new THREE.Float32BufferAttribute(starBright, 1));

        const starMat = new THREE.ShaderMaterial({
          uniforms: {
            uTime: { value: 0 },
            uSize: { value: CONFIG.starSize },
            uFlicker: { value: CONFIG.starFlicker },
            uColor: { value: hexToVec3(CONFIG.starColor) },
            uRes: { value: new THREE.Vector2(width, height) },
          },
          vertexShader: `
            attribute float seed; attribute float bright;
            uniform float uTime; uniform float uSize; uniform float uFlicker; uniform vec2 uRes;
            varying float vTw;
            void main(){
              vec4 mv = modelViewMatrix * vec4(position, 1.0);
              float tw = 0.6 + 0.4 * sin(uTime * uFlicker + seed);
              vTw = bright * tw;
              gl_PointSize = max(uSize * uRes.y / 900.0 * (90.0 / max(-mv.z, 1.0)), 1.0);
              gl_Position = projectionMatrix * mv;
            }
          `,
          fragmentShader: `
            uniform vec3 uColor; varying float vTw;
            void main(){
              vec2 p = gl_PointCoord - 0.5; float l = length(p); if (l > 0.5) discard;
              float core = smoothstep(0.5, 0.0, l);
              gl_FragColor = vec4(uColor, core * vTw);
            }
          `,
          transparent: true,
          depthWrite: false,
          depthTest: true,
          blending: THREE.AdditiveBlending,
        });
        const starMesh = new THREE.Points(starGeo, starMat);
        starMesh.frustumCulled = false;
        starMesh.layers.enable(LAYERS.ENTIRE_SCENE);
        scene.add(starMesh);

        // Ambient atmosphere motes
        const atmoGeo = new THREE.BufferGeometry();
        const atmoPos = [];
        const atmoSize = [];
        const atmoSeed = [];
        for (let i = 0; i < CONFIG.atmoCount; i++) {
          atmoPos.push(Math.random() * 2 - 1, Math.random() * 2 - 1, Math.random() * 2 - 1);
          atmoSize.push(CONFIG.atmoSize * (0.4 + Math.random()));
          atmoSeed.push(Math.random() * 100);
        }
        atmoGeo.setAttribute('position', new THREE.Float32BufferAttribute(atmoPos, 3));
        atmoGeo.setAttribute('size', new THREE.Float32BufferAttribute(atmoSize, 1));
        atmoGeo.setAttribute('seed', new THREE.Float32BufferAttribute(atmoSeed, 1));

        const atmoMat = new THREE.ShaderMaterial({
          uniforms: {
            uTime: { value: 0 },
            uRes: { value: new THREE.Vector2(width, height) },
            uColor: { value: hexToVec3(CONFIG.atmoColor) },
          },
          vertexShader: `
            attribute float size; attribute float seed; uniform float uTime; uniform vec2 uRes;
            varying float vA;
            vec3 warp(vec3 p, float t){ float c=0.9,a=1.9,b=0.02,s=0.05; p*=2.;
              p.x+=c*sin(s*t+a*p.y)+t*b; p.y+=c*cos(s*t+a*p.x); p.y+=c*sin(s*t+a*p.z)+t*b;
              p.z+=c*cos(s*t+a*p.y); p.z+=c*sin(s*t+a*p.x)+t*b; p.x+=c*cos(s*t+a*p.z);
              return cos(p+vec3(1,2,4)); }
            void main(){
              vec3 v = position*4.0 + warp(position, uTime)*1.2;
              vec4 mv = modelViewMatrix * vec4(v, 1.0);
              float r = length(v); float farF = 1.0 - smoothstep(5.0, 6.5, r); float nearF = smoothstep(0.0, 0.5, -mv.z);
              vA = farF * nearF;
              gl_PointSize = size * uRes.y / 900.0 / -mv.z; gl_PointSize = max(gl_PointSize, 1.0);
              gl_Position = projectionMatrix * mv;
            }
          `,
          fragmentShader: `
            uniform vec3 uColor; varying float vA;
            void main(){ vec2 p = gl_PointCoord - 0.5; float l = length(p); if (l > 0.5) discard;
              float tex = smoothstep(0.5, 0.0, l); gl_FragColor = vec4(uColor * tex, tex * vA * 0.55); }
          `,
          transparent: true,
          depthWrite: false,
          depthTest: false,
          blending: THREE.AdditiveBlending,
        });
        const atmoMesh = new THREE.Points(atmoGeo, atmoMat);
        atmoMesh.frustumCulled = false;
        atmoMesh.layers.enable(LAYERS.ENTIRE_SCENE);
        scene.add(atmoMesh);

        let planetTime = 0;
        let cloudTime = 0;
        let starTime = 0;
        let markerTime = 0;
        let planetShaderUniforms = null;
        const cloudShells = [];
        let markerUniforms = null;

        // Fallback procedural planet creation
        function createProceduralDayTexture() {
          const c = document.createElement('canvas');
          c.width = 1024; c.height = 512;
          const ctx = c.getContext('2d');
          ctx.fillStyle = '#0a2244';
          ctx.fillRect(0, 0, 1024, 512);
          ctx.fillStyle = '#1c4a2b';
          for (let i = 0; i < 30; i++) {
            ctx.beginPath();
            ctx.arc(Math.random() * 1024, Math.random() * 512, 40 + Math.random() * 100, 0, Math.PI * 2);
            ctx.fill();
          }
          return new THREE.CanvasTexture(c);
        }
        function createProceduralNightTexture() {
          const c = document.createElement('canvas');
          c.width = 1024; c.height = 512;
          const ctx = c.getContext('2d');
          ctx.fillStyle = '#000000';
          ctx.fillRect(0, 0, 1024, 512);
          ctx.fillStyle = '#ffeaa7';
          for (let i = 0; i < 400; i++) {
            ctx.beginPath();
            ctx.arc(Math.random() * 1024, Math.random() * 512, Math.random() * 2, 0, Math.PI * 2);
            ctx.fill();
          }
          return new THREE.CanvasTexture(c);
        }

        function setupPlanet(mesh, nightTex, dayTex) {
          mesh.geometry.computeBoundingSphere();
          const bs = mesh.geometry.boundingSphere;
          const scale = CONFIG.planetRadius / (bs ? bs.radius : 1.0);
          mesh.scale.setScalar(scale);

          const mat = (mesh.material ? mesh.material.clone() : new THREE.MeshStandardMaterial({ map: dayTex }));
          mat.metalness = 0;
          mat.roughness = 1;
          mat.envMapIntensity = 0;

          mat.onBeforeCompile = (shader) => {
            planetShaderUniforms = shader.uniforms;
            shader.uniforms.time = { value: 0 };
            shader.uniforms.noiseScale = { value: 30 };
            shader.uniforms.speedX = { value: 1.5 };
            shader.uniforms.speedY = { value: 2.0 };
            shader.uniforms.speedZ = { value: 2.5 };
            shader.uniforms.rimColor = { value: hexToVec3(CONFIG.rimColor) };
            shader.uniforms.rimPower = { value: CONFIG.rimPower };
            shader.uniforms.nightBlendTexture = { value: nightTex };
            shader.uniforms.nightLights = { value: CONFIG.nightLights };
            shader.uniforms.terrainDepth = { value: CONFIG.terrainDepth };
            shader.uniforms.terrainShade = { value: CONFIG.terrainShade };
            shader.uniforms.oceanGlint = { value: CONFIG.oceanGlint };
            shader.uniforms.oceanDeep = { value: CONFIG.oceanDeep };
            shader.uniforms.oceanFlow = { value: CONFIG.oceanFlow };
            shader.uniforms.oceanFlowSpeed = { value: CONFIG.oceanFlowSpeed };
            shader.uniforms.oceanFlowScale = { value: CONFIG.oceanFlowScale };

            shader.vertexShader = `varying vec2 vCustomUv;\n` + shader.vertexShader;
            shader.vertexShader = shader.vertexShader.replace('void main() {', 'void main() { vCustomUv = uv;');

            shader.fragmentShader = `
              varying vec2 vCustomUv;
              uniform float time; uniform float noiseScale;
              uniform float speedX; uniform float speedY; uniform float speedZ;
              uniform vec3 rimColor; uniform float rimPower;
              uniform sampler2D nightBlendTexture; uniform float nightLights;
              uniform float terrainDepth; uniform float terrainShade;
              uniform float oceanGlint; uniform float oceanDeep;
              uniform float oceanFlow; uniform float oceanFlowSpeed; uniform float oceanFlowScale;
              ${SNOISE}
            ` + shader.fragmentShader;

            shader.fragmentShader = shader.fragmentShader.replace(
              '#include <dithering_fragment>',
              `
              #include <dithering_fragment>
              vec3 normalizedNormal = normalize(vNormal);
              vec3 viewDir = normalize(vViewPosition);
              float rim = 1.0 - max(dot(viewDir, normalizedNormal), 0.0);
              rim = pow(rim, rimPower); rim = pow(rim, 1.5); rim *= 0.7;
              vec3 currentColor = gl_FragColor.rgb;
              float blueDom = currentColor.b - max(currentColor.r, currentColor.g);
              float waterMask = clamp(smoothstep(-0.005, 0.03, blueDom), 0.0, 1.0);
              float shimmer = snoise(vec3(vCustomUv.x * noiseScale + time * speedX, vCustomUv.y * noiseScale - time * speedY, time * speedZ));
              gl_FragColor.rgb += waterMask * shimmer * 0.025;
              float fT = time * oceanFlowSpeed * 4.0;
              float fS = 4.0 * oceanFlowScale;
              float warp = snoise(vec3(vCustomUv.x * fS - fT * 0.5, vCustomUv.y * fS + fT * 0.4, fT * 0.5));
              float flow = snoise(vec3(vCustomUv.x * fS * 2.0 + fT * 0.6 + warp, vCustomUv.y * fS * 2.0 - fT * 0.5, fT * 0.7));
              flow = warp * 0.6 + flow * 0.4;
              gl_FragColor.rgb += waterMask * flow * 0.12 * oceanFlow;
              gl_FragColor.rgb = mix(gl_FragColor.rgb, vec3(0.01, 0.06, 0.16), waterMask * oceanDeep);
              vec3 finalColor = mix(gl_FragColor.rgb, rimColor, rim);
              gl_FragColor = vec4(finalColor, 1.0);
              vec3 surfPos = -vViewPosition;
              float terrH = dot(texture2D(map, vCustomUv).rgb, vec3(0.299, 0.587, 0.114));
              vec3 sigX = dFdx(surfPos), sigY = dFdy(surfPos);
              vec3 vR1 = cross(sigY, normalizedNormal), vR2 = cross(normalizedNormal, sigX);
              float fDet = dot(sigX, vR1);
              vec3 vGrad = sign(fDet) * (dFdx(terrH) * vR1 + dFdy(terrH) * vR2);
              vec3 bumpedNormal = normalize(abs(fDet) * normalizedNormal - terrainDepth * vGrad);
              vec3 shadeNormal = mix(bumpedNormal, normalizedNormal, waterMask);
              vec3 cityLights = texture2D(nightBlendTexture, vCustomUv).rgb * gl_FragColor.rgb * nightLights;
              vec3 viewSunDir = normalize(vec3(-0.9, 0.18, 0.4));
              float ndl = dot(normalizedNormal, viewSunDir);
              float dayAmt = smoothstep(-0.05, 0.35, ndl);
              float relief = dot(shadeNormal, viewSunDir) - ndl;
              gl_FragColor.rgb *= clamp(1.0 + relief * terrainShade * dayAmt, 0.55, 1.6);
              float nightFactor  = smoothstep(0.18, -0.30, ndl);
              float lightsFactor = smoothstep(0.30, -0.35, ndl);
              gl_FragColor.rgb = mix(gl_FragColor.rgb, gl_FragColor.rgb * 0.08, nightFactor);
              gl_FragColor.rgb += cityLights * lightsFactor;
              vec3 halfDir = normalize(viewSunDir + viewDir);
              float ripple = snoise(vec3(vCustomUv * 240.0, time * 4.0));
              float ndh = max(dot(normalizedNormal, halfDir) + ripple * 0.02, 0.0);
              float glint = pow(ndh, 140.0);
              gl_FragColor.rgb += glint * waterMask * dayAmt * oceanGlint * vec3(1.0, 0.97, 0.88);
              `
            );
          };

          mesh.material = mat;
          mesh.layers.enable(LAYERS.ENTIRE_SCENE);
          mesh.layers.enable(LAYERS.BLOOM_SCENE);
          planetGroup.add(mesh);
        }

        // Initialize Earth
        const fallbackMesh = new THREE.Mesh(new THREE.SphereGeometry(CONFIG.planetRadius, 64, 64));
        setupPlanet(fallbackMesh, createProceduralNightTexture(), createProceduralDayTexture());

        let planetLoaded = true;
        let loadStartTime = performance.now() / 1000;
        const ENTRY_DUR = 1.9;
        const ENTRY_START_Y = -6.5;

        // Resize handler
        const handleResize = () => {
          width = window.innerWidth;
          height = window.innerHeight;
          camera.aspect = width / height;
          camera.updateProjectionMatrix();

          renderer.setSize(width, height);
          torusComposer.setSize(width, height);
          bloomComposer.setSize(width, height);
          finalComposer.setSize(width, height);

          starMat.uniforms.uRes.value.set(width, height);
          atmoMat.uniforms.uRes.value.set(width, height);
          if (markerUniforms) markerUniforms.uRes.value.set(width, height);
        };
        window.addEventListener('resize', handleResize);

        let curP = 0;
        let curX = STOPS_X[0].v;
        let curY = STOPS_Y[0].v;
        let curS = STOPS_S[0].v;
        let spinPhase = 0;
        let lastTime = performance.now();

        function animate(now) {
          animId = requestAnimationFrame(animate);

          const perfNow = now * 0.001;
          let dt = (now - lastTime) * 0.001;
          lastTime = now;
          if (dt > 0.05) dt = 0.05;

          planetTime += dt / 12;
          cloudTime += dt / 20;
          starTime += dt;
          markerTime += dt;

          if (planetShaderUniforms) planetShaderUniforms.time.value = planetTime;
          cloudShells.forEach(({ mesh, layer }) => {
            if (layer.shader) layer.shader.uniforms.uTime.value = cloudTime;
            mesh.rotation.y += dt * CONFIG[layer.spinKey];
          });
          starMat.uniforms.uTime.value = starTime;
          atmoMat.uniforms.uTime.value = perfNow * CONFIG.atmoSpeed * 8;
          atmoMesh.position.copy(camera.position);
          finalPass.uniforms.iTime.value = perfNow * CONFIG.atmoSpeed * 8;
          if (markerUniforms) markerUniforms.uTime.value = markerTime;

          glowMesh.quaternion.copy(camera.quaternion);

          const maxScroll = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
          const pTarget = clamp(window.scrollY / maxScroll, 0, 1);
          curP += (pTarget - curP) * Math.min(1, dt * 4.5);

          const sideScale = clamp(window.innerWidth / 1200, 0.5, 1);
          const targetX = sample(STOPS_X, curP) * sideScale;
          const targetY = sample(STOPS_Y, curP);
          const targetS = sample(STOPS_S, curP);

          const k = Math.min(1, dt * 3.2);
          curX += (targetX - curX) * k;
          curY += (targetY - curY) * k;
          curS += (targetS - curS) * k;

          let entryY = 0;
          if (planetLoaded) {
            const elapsed = perfNow - loadStartTime;
            const entryProgress = clamp(elapsed / ENTRY_DUR, 0, 1);
            const ease = 1 - Math.pow(1 - entryProgress, 3);
            entryY = ENTRY_START_Y * (1 - ease);
          }

          worldGroup.position.set(curX, curY + entryY, 0);
          worldGroup.scale.setScalar(curS);

          spinPhase += dt * CONFIG.spin;
          planetGroup.rotation.y = CONFIG.initRotation + spinPhase + curP * Math.PI * 1.6;

          camera.layers.set(LAYERS.TORUS_SCENE);
          torusComposer.render();

          camera.layers.set(LAYERS.BLOOM_SCENE);
          bloomComposer.render();

          camera.layers.set(LAYERS.ENTIRE_SCENE);
          finalComposer.render();
        }

        animId = requestAnimationFrame(animate);

        cleanupFn = () => {
          window.removeEventListener('resize', handleResize);
          if (animId) cancelAnimationFrame(animId);
          renderer.dispose();
        };
      } catch (err) {
        console.warn('Three.js scene init error:', err);
      }
    }

    initPlanet();

    return () => {
      cleanupFn();
      observer.disconnect();
    };
  }, []);

  return (
    <div className="landing-page-wrap">
      {/* Fixed WebGL Background Canvas */}
      <canvas ref={canvasRef} className="planet-canvas" />

      {/* SECTION 1: HERO */}
      <header className="landing-hero">
        <nav className="landing-nav">
          <div className="landing-brand">
            <span className="landing-brand-mark">▲</span> WebFort
          </div>
          <ul className="landing-nav-links">
            <li><a href="#features">Features</a></li>
            <li><a href="#features">Mutation Gauntlet</a></li>
            <li><a href="#solutions">Live Verification</a></li>
            <li><a href="#cta">Proof Engine</a></li>
          </ul>
          <button onClick={onLaunchConsole} className="landing-btn landing-btn-ghost">
            Launch Console →
          </button>
        </nav>

        <div className="landing-hero-inner">
          <h1 className="landing-hero-title" data-reveal style={{ '--rd': '60ms' }}>
            Scale Smarter,<br />Not <em>Harder</em>
          </h1>
          <p className="landing-hero-sub" data-reveal style={{ '--rd': '180ms' }}>
            AI-driven adaptive WAF with continuous rule verification, mutation gauntlets, and signed proof reports — all in one unified command center.
          </p>
          <div className="landing-hero-actions" data-reveal style={{ '--rd': '300ms' }}>
            <button onClick={onLaunchConsole} className="landing-btn landing-btn-primary">
              Launch WebFort Console
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M5 12h14"></path>
                <path d="m12 5 7 7-7 7"></path>
              </svg>
            </button>
            <a href="#solutions" className="landing-btn landing-btn-outline">
              Explore Live Gauntlet
            </a>
          </div>
        </div>

        <div className="landing-logos" data-reveal style={{ '--rd': '420ms' }}>
          <div className="landing-logos-label">Trusted by fast-moving security teams</div>
          <div className="landing-logos-row">
            <span className="landing-logo">Nimbus</span>
            <span className="landing-logo">Pluma</span>
            <span className="landing-logo">Citrus</span>
            <span className="landing-logo">Spider</span>
            <span className="landing-logo">Helod</span>
            <span className="landing-logo">Vertx</span>
          </div>
        </div>
      </header>

      {/* SECTION 2: FEATURES */}
      <section className="landing-section" id="features">
        <div className="landing-head">
          <span className="landing-eyebrow" data-reveal>Everything in orbit</span>
          <h2 data-reveal style={{ '--rd': '80ms' }}>One platform to run the entire defense engine</h2>
          <p data-reveal style={{ '--rd': '160ms' }}>
            Stop stitching fragile rules together. WebFort unifies vulnerability triage, adversarial mutation verification, and automated hardening into a single surface your whole team can trust.
          </p>
        </div>

        <div className="landing-feature-grid">
          {/* Card 1 */}
          <div className="landing-card" data-reveal style={{ '--rd': '0ms' }}>
            <div className="landing-card-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="3" width="6" height="6" rx="1.5" />
                <rect x="15" y="15" width="6" height="6" rx="1.5" />
                <path d="M6 9v3a3 3 0 0 0 3 3h3" />
              </svg>
            </div>
            <h3>Mutation Gauntlet</h3>
            <p>Systematically mutate payloads across encodings, case, whitespace, and HPP to guarantee zero bypass under adversarial variation.</p>
          </div>

          {/* Card 2 */}
          <div className="landing-card" data-reveal style={{ '--rd': '90ms' }}>
            <div className="landing-card-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                <path d="M4 19V5" />
                <path d="M4 19h16" />
                <path d="M8 16v-4" />
                <path d="M13 16V8" />
                <path d="M18 16v-7" />
              </svg>
            </div>
            <h3>Vulnerability Triage</h3>
            <p>Real-time scoring and ZAP ingestion prioritize the exploit vectors that actually threaten your production app.</p>
          </div>

          {/* Card 3 */}
          <div className="landing-card" data-reveal style={{ '--rd': '180ms' }}>
            <div className="landing-card-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
                <circle cx="9" cy="7" r="4" />
                <path d="M22 21v-2a4 4 0 0 0-3-3.87" />
                <path d="M16 3.13a4 4 0 0 1 0 7.75" />
              </svg>
            </div>
            <h3>Auto-Tighten Loop</h3>
            <p>Iteratively harden rules from normalizer fixes to allowlists while strictly preventing benign traffic regression.</p>
          </div>

          {/* Card 4 */}
          <div className="landing-card" data-reveal style={{ '--rd': '270ms' }}>
            <div className="landing-card-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                <path d="M13 2 3 14h9l-1 8 10-12h-9l1-8Z" />
              </svg>
            </div>
            <h3>Instant Triggers</h3>
            <p>Generate and deploy verified ModSecurity and Coraza SecLang rules across your stack in milliseconds, not minutes.</p>
          </div>

          {/* Card 5 */}
          <div className="landing-card" data-reveal style={{ '--rd': '360ms' }}>
            <div className="landing-card-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" />
                <path d="m9 12 2 2 4-4" />
              </svg>
            </div>
            <h3>Signed Proof Reports</h3>
            <p>Cryptographic ed25519-signed proof reports carrying mutation stats, Wilson CIs, and tamper-evident audit evidence.</p>
          </div>

          {/* Card 6 */}
          <div className="landing-card" data-reveal style={{ '--rd': '450ms' }}>
            <div className="landing-card-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10" />
                <path d="M2 12h20" />
                <path d="M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20Z" />
              </svg>
            </div>
            <h3>Global by Default</h3>
            <p>Multi-region, low-latency edge inspection everywhere your customers and APIs happen to be.</p>
          </div>
        </div>
      </section>

      {/* SECTION 3: SHOWCASE + STATS */}
      <section className="landing-section" id="solutions">
        <div className="landing-showcase-grid">
          <div className="landing-showcase-copy">
            <span className="landing-eyebrow" data-reveal>Built for momentum</span>
            <h2 data-reveal style={{ '--rd': '90ms' }}>See the whole threat surface verified in real time</h2>
            <p data-reveal style={{ '--rd': '180ms' }}>
              Every attack mutation, every bypass attempt, every verified virtual patch — rendered live. WebFort gives security engineers the altitude to spot evasion and the controls to harden instantly.
            </p>
            <button onClick={onLaunchConsole} className="landing-btn landing-btn-primary" data-reveal style={{ '--rd': '270ms' }}>
              Open Security Dashboard
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M5 12h14"></path>
                <path d="m12 5 7 7-7 7"></path>
              </svg>
            </button>
          </div>

          {/* Right Dashboard Mock */}
          <div className="landing-dashboard" data-reveal style={{ '--rd': '160ms' }}>
            <div className="landing-dash-top">
              <span>Pipeline · Q3</span>
              <div className="landing-dash-live">Live</div>
            </div>

            <div className="landing-dash-bars">
              <div className="landing-dash-bar" style={{ '--h': '62%', '--del': '0ms' }} />
              <div className="landing-dash-bar" style={{ '--h': '88%', '--del': '90ms' }} />
              <div className="landing-dash-bar" style={{ '--h': '47%', '--del': '180ms' }} />
              <div className="landing-dash-bar" style={{ '--h': '95%', '--del': '270ms' }} />
              <div className="landing-dash-bar" style={{ '--h': '71%', '--del': '360ms' }} />
              <div className="landing-dash-bar" style={{ '--h': '80%', '--del': '450ms' }} />
              <div className="landing-dash-bar" style={{ '--h': '58%', '--del': '540ms' }} />
            </div>

            <div className="landing-dash-rows">
              <div className="landing-dash-row">
                <span>New leads 90%</span>
                <div className="landing-dash-track">
                  <div className="landing-dash-fill" style={{ '--w': '90%' }} />
                </div>
              </div>
              <div className="landing-dash-row">
                <span>Qualified 72%</span>
                <div className="landing-dash-track">
                  <div className="landing-dash-fill" style={{ '--w': '72%' }} />
                </div>
              </div>
              <div className="landing-dash-row">
                <span>In negotiation 48%</span>
                <div className="landing-dash-track">
                  <div className="landing-dash-fill" style={{ '--w': '48%' }} />
                </div>
              </div>
              <div className="landing-dash-row">
                <span>Closed won 34%</span>
                <div className="landing-dash-track">
                  <div className="landing-dash-fill" style={{ '--w': '34%' }} />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Stats */}
        <div className="landing-stats">
          <div className="landing-stat" data-reveal style={{ '--rd': '0ms' }}>
            <div className="landing-stat-value">3.4×</div>
            <div className="landing-stat-label">Faster pipeline velocity</div>
          </div>
          <div className="landing-stat" data-reveal style={{ '--rd': '80ms' }}>
            <div className="landing-stat-value">92%</div>
            <div className="landing-stat-label">Lead capture accuracy</div>
          </div>
          <div className="landing-stat" data-reveal style={{ '--rd': '160ms' }}>
            <div className="landing-stat-value">11k+</div>
            <div className="landing-stat-label">Teams scaling on WebFort</div>
          </div>
          <div className="landing-stat" data-reveal style={{ '--rd': '240ms' }}>
            <div className="landing-stat-value">$2.1B</div>
            <div className="landing-stat-label">Revenue influenced</div>
          </div>
        </div>
      </section>

      {/* SECTION 4: CTA + FOOTER */}
      <section className="landing-section" id="cta">
        <div className="landing-cta-card">
          <span className="landing-eyebrow" data-reveal style={{ '--rd': '60ms' }}>Ready when you are</span>
          <h2 data-reveal style={{ '--rd': '140ms' }}>Put your growth on a new trajectory</h2>
          <p data-reveal style={{ '--rd': '220ms' }}>
            Launch in minutes. No credit card. Cancel anytime. Join thousands of teams compounding resilience and revenue on WebFort.
          </p>
          <div className="landing-hero-actions" data-reveal style={{ '--rd': '300ms' }}>
            <button onClick={onLaunchConsole} className="landing-btn landing-btn-primary">
              Start Free Right Now
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M5 12h14"></path>
                <path d="m12 5 7 7-7 7"></path>
              </svg>
            </button>
            <button onClick={onLaunchConsole} className="landing-btn landing-btn-outline">
              Open Security Console
            </button>
          </div>
        </div>

        <footer className="landing-footer">
          <div className="landing-footer-brand">
            <div className="landing-brand">
              <span className="landing-brand-mark">▲</span> WebFort
            </div>
            <p>The revenue command center and adaptive defense platform for ambitious teams.</p>
          </div>

          <div className="landing-footer-cols">
            <div className="landing-footer-col">
              <span>Product</span>
              <a href="#features">Features</a>
              <a href="#solutions">Solutions</a>
              <a href="#features">Plans</a>
              <a href="#features">Learning</a>
            </div>
            <div className="landing-footer-col">
              <span>Company</span>
              <a href="#top">About</a>
              <a href="#top">Careers</a>
              <a href="#top">Blog</a>
            </div>
            <div className="landing-footer-col">
              <span>Legal</span>
              <a href="#top">Privacy</a>
              <a href="#top">Terms</a>
              <a href="#top">Security</a>
            </div>
          </div>
        </footer>

        <div className="landing-copyright">
          © {new Date().getFullYear()} WebFort, Inc. — Built among the stars.
        </div>
      </section>
    </div>
  );
}
