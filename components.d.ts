export {}

declare module 'vue' {
  export interface GlobalComponents {
    HelloWorld: typeof import('./src/components/Generator.vue')['default']
  }
}
