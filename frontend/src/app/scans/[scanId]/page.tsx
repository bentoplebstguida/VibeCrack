import ScanDetailClient from "./ScanDetailClient";

export function generateStaticParams() {
  return [{ scanId: "detail" }];
}

export default function ScanDetailPage() {
  return <ScanDetailClient />;
}
