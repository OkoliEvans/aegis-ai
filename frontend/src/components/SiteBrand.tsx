type SiteBrandProps = {
  className?: string;
};

export function SiteBrand({ className }: SiteBrandProps) {
  return (
    <div className={className ? `site-brand ${className}` : "site-brand"}>
      <span className="brand-mark" aria-hidden="true">
        <span className="brand-mark__inner" />
      </span>
      <span>Aegis Guard</span>
    </div>
  );
}
