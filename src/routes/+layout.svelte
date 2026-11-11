<script lang="ts">
  import "../app.css";
  let { children } = $props();
</script>

<div class="h-screen w-screen flex bg-[#050709] text-zinc-100 antialiased overflow-hidden select-none">
  {@render children()}
</div>
